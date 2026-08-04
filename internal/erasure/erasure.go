// Package erasure wraps Reed–Solomon coding: it splits a blob into K data
// shards plus M parity shards such that ANY K of the K+M shards reconstruct the
// original ("RAID-5/6 over the internet"). revika erasure-codes the encrypted
// bytes of each chunk, so shards are opaque ciphertext fragments.
//
// Encode is deterministic: the same input always yields byte-identical shards.
// The repair layer relies on this — regenerating a lost shard reproduces its
// exact content address, so manifests never need rewriting after a repair.
//
// A little framing is needed because Reed–Solomon works on fixed, equal-sized
// shards and zero-pads the final one. Encode prepends an 8-byte big-endian
// length header to the payload so Decode can recover the exact original length.
//
// Defence controls (security/Defence.md; primitives P6, P25 in security/frameworks.md):
//   SC-36 (Distributed Processing and Storage)    — any K of K+M shards reconstruct; deterministic
//         Encode lets repair regenerate lost shards without rewriting manifests. Compl. CP-10.
//   SC-4  (Information in Shared System Resources) — equal-length shards normalize on-wire size.
package erasure

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const headerSize = 8 // uint64 original length, big-endian

// Params selects the code rate: K data shards + M parity shards.
type Params struct {
	K int // data shards (must be >= 1)
	M int // parity shards (must be >= 1)
}

// N is the total number of shards produced (K + M).
func (p Params) N() int { return p.K + p.M }

func (p Params) validate() error {
	if p.K < 1 || p.M < 1 {
		return fmt.Errorf("erasure: invalid params K=%d M=%d (both must be >= 1)", p.K, p.M)
	}
	if p.N() > 256 {
		return fmt.Errorf("erasure: K+M=%d exceeds 256", p.N())
	}
	return nil
}

func encoder(p Params) (reedsolomon.Encoder, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return reedsolomon.New(p.K, p.M)
}

// Encode splits data into p.N() shards (the first p.K are data, the rest
// parity). The returned shards are all the same length.
func Encode(p Params, data []byte) ([][]byte, error) {
	enc, err := encoder(p)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, headerSize+len(data))
	binary.BigEndian.PutUint64(payload[:headerSize], uint64(len(data)))
	copy(payload[headerSize:], data)

	shards, err := enc.Split(payload)
	if err != nil {
		return nil, fmt.Errorf("erasure: split: %w", err)
	}
	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("erasure: encode: %w", err)
	}
	return shards, nil
}

// Decode reconstructs the original data from shards. shards must have length
// p.N(); missing shards are represented by nil entries. It succeeds as long as
// at least p.K shards are present, and returns an error otherwise.
func Decode(p Params, shards [][]byte) ([]byte, error) {
	enc, err := encoder(p)
	if err != nil {
		return nil, err
	}
	if len(shards) != p.N() {
		return nil, fmt.Errorf("erasure: got %d shards, want %d", len(shards), p.N())
	}
	present := 0
	for _, s := range shards {
		if s != nil {
			present++
		}
	}
	if present < p.K {
		return nil, fmt.Errorf("erasure: only %d of %d shards present, need %d", present, p.N(), p.K)
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("erasure: reconstruct: %w", err)
	}

	shardLen := len(shards[0])
	var buf bytes.Buffer
	buf.Grow(p.K * shardLen)
	if err := enc.Join(&buf, shards, p.K*shardLen); err != nil {
		return nil, fmt.Errorf("erasure: join: %w", err)
	}
	payload := buf.Bytes()
	if len(payload) < headerSize {
		return nil, fmt.Errorf("erasure: payload too short (%d bytes)", len(payload))
	}
	origLen := binary.BigEndian.Uint64(payload[:headerSize])
	if uint64(len(payload)-headerSize) < origLen {
		return nil, fmt.Errorf("erasure: declared length %d exceeds payload %d", origLen, len(payload)-headerSize)
	}
	return payload[headerSize : headerSize+origLen], nil
}
