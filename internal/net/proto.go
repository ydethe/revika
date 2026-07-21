// Package net is revika's libp2p layer: it puts the content-addressed shard
// store (internal/store) on the wire so a Node can serve shards to remote Users
// and a User can treat a remote Node as just another store.Store.
//
// It defines two versioned stream protocols from the architecture doc:
//
//	/revika/shard/1.0.0 — PUT / GET / HAS / DELETE a shard by content address.
//	/revika/probe/1.0.0 — proof-of-possession challenge/response for repair.
//
// The design keeps nodes dumb and untrusted: every byte on the wire is an
// already-encrypted, erasure-coded shard addressed by hash, so a Node never
// learns anything about the content it holds.
//
// Framing. One request/response per stream, then the stream is closed. Each
// message is a single opcode/status byte followed by fixed-width IDs and
// length-prefixed byte blobs (4-byte big-endian length). This is deliberately
// minimal — no protobuf, no external codec — because the payloads are opaque
// blobs and the verb set is tiny.
package net

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/protocol"

	"revika/internal/ledger"
	"revika/internal/store"
)

// Protocol IDs. Semantic-versioned so upgrades are negotiable via libp2p's
// multistream muxer.
const (
	ShardProtocol protocol.ID = "/revika/shard/1.0.0"
	ProbeProtocol protocol.ID = "/revika/probe/1.0.0"
)

// op is the request verb on the shard protocol (first byte of a request).
type op byte

const (
	opPut    op = 1
	opGet    op = 2
	opHas    op = 3
	opDelete op = 4
)

// status is the first byte of every response.
type status byte

const (
	statusOK           status = 0 // request succeeded
	statusNotFound     status = 1 // shard absent (maps to store.ErrNotFound)
	statusCorrupt      status = 2 // stored bytes failed their hash (store.ErrCorrupt)
	statusError        status = 3 // server-side error; a message blob follows
	statusUnauthorized status = 4 // missing/invalid auth token, or not the shard's owner
	statusQuotaExceeded status = 5 // owner is over their storage quota
)

// MaxShardSize caps the bytes accepted for a single shard, a guard against a
// malicious or buggy peer trying to exhaust memory with an oversized frame. A
// shard is at most one chunk / K plus framing overhead; 64 MiB is comfortably
// above any sane configuration while still bounding a single allocation.
const MaxShardSize = 64 << 20

// NonceSize is the length of a probe challenge nonce.
const NonceSize = 32

// ErrRemote is returned to a client when the server reported statusError.
type ErrRemote struct{ Msg string }

func (e *ErrRemote) Error() string { return "revika/net: remote error: " + e.Msg }

// ErrUnauthorized is surfaced to a client when a PUT/DELETE is rejected because
// its auth token was missing/invalid or the caller does not own the shard.
var ErrUnauthorized = errors.New("revika/net: unauthorized")

// ErrQuotaExceeded is surfaced to a client when a PUT is rejected because the
// owner is over their storage quota.
var ErrQuotaExceeded = errors.New("revika/net: quota exceeded")

// --- low-level framing helpers -------------------------------------------

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// writeID writes a 32-byte content address.
func writeID(w io.Writer, id store.ShardID) error {
	_, err := w.Write(id[:])
	return err
}

// readID reads a 32-byte content address.
func readID(r io.Reader) (store.ShardID, error) {
	var id store.ShardID
	_, err := io.ReadFull(r, id[:])
	return id, err
}

// writeBlob writes a 4-byte big-endian length followed by the bytes.
func writeBlob(w io.Writer, b []byte) error {
	if len(b) > MaxShardSize {
		return fmt.Errorf("revika/net: blob of %d bytes exceeds max %d", len(b), MaxShardSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// readBlob reads a length-prefixed blob, rejecting anything larger than max.
func readBlob(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("revika/net: blob of %d bytes exceeds max %d", n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readNonce reads a fixed-size probe nonce.
func readNonce(r io.Reader) ([]byte, error) {
	buf := make([]byte, NonceSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// statusToErr maps a response status byte to the corresponding store error, so
// a NetStore surfaces the same errors as a local store.Store.
func statusToErr(s status, msg string) error {
	switch s {
	case statusOK:
		return nil
	case statusNotFound:
		return store.ErrNotFound
	case statusCorrupt:
		return store.ErrCorrupt
	case statusUnauthorized:
		return ErrUnauthorized
	case statusQuotaExceeded:
		return ErrQuotaExceeded
	case statusError:
		return &ErrRemote{Msg: msg}
	default:
		return fmt.Errorf("revika/net: unknown status byte %d", s)
	}
}

// errToStatus maps a store or ledger error to the status byte a server sends
// back.
func errToStatus(err error) status {
	switch {
	case err == nil:
		return statusOK
	case errors.Is(err, store.ErrNotFound):
		return statusNotFound
	case errors.Is(err, store.ErrCorrupt):
		return statusCorrupt
	case errors.Is(err, ledger.ErrUnauthorized), errors.Is(err, ErrUnauthorized):
		return statusUnauthorized
	case errors.Is(err, ledger.ErrQuotaExceeded), errors.Is(err, ErrQuotaExceeded):
		return statusQuotaExceeded
	default:
		return statusError
	}
}
