// Package repair keeps stored data durable. Erasure coding only *delays* data
// loss: as shards disappear (nodes leave, disks die), every chunk drifts toward
// the point where fewer than K shards remain and the data is gone forever.
// Repair is the maintenance loop that pushes back — it probes which shards
// survive and regenerates the missing ones while enough remain to reconstruct.
//
// Two properties make this clean:
//   - Repair works purely on ciphertext shards; it never needs the encryption
//     key. (In capability terms it needs only a verify-cap.)
//   - erasure.Encode is deterministic, so a regenerated shard reproduces its
//     exact content address. Repair restores the *same* shard IDs, so the
//     manifest never changes.
package repair

import (
	"context"
	"errors"
	"fmt"

	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// ChunkStatus is the shard-availability of a single chunk.
type ChunkStatus struct {
	Index   int
	Present int   // shards currently in the store
	Total   int   // N = K + M
	Missing []int // shard positions absent from the store
}

// Recoverable reports whether the chunk still has at least K shards.
func (c ChunkStatus) Recoverable(k int) bool { return c.Present >= k }

// Healthy reports whether the chunk has all its shards.
func (c ChunkStatus) Healthy() bool { return len(c.Missing) == 0 }

// Report is the availability of every chunk in a file.
type Report struct {
	Chunks []ChunkStatus
}

// Healthy reports whether every chunk has all shards present.
func (r Report) Healthy() bool {
	for _, c := range r.Chunks {
		if !c.Healthy() {
			return false
		}
	}
	return true
}

// MissingShards is the total number of absent shards across all chunks.
func (r Report) MissingShards() int {
	n := 0
	for _, c := range r.Chunks {
		n += len(c.Missing)
	}
	return n
}

// Check probes shard availability for every chunk of m without moving any data.
func Check(ctx context.Context, s store.Store, m pipeline.FileManifest) (Report, error) {
	rep := Report{Chunks: make([]ChunkStatus, len(m.Chunks))}
	for i, ref := range m.Chunks {
		st := ChunkStatus{Index: i, Total: len(ref.Shards)}
		for pos, id := range ref.Shards {
			ok, err := s.Has(ctx, id)
			if err != nil {
				return Report{}, fmt.Errorf("repair: probe chunk %d shard %d: %w", i, pos, err)
			}
			if ok {
				st.Present++
			} else {
				st.Missing = append(st.Missing, pos)
			}
		}
		rep.Chunks[i] = st
	}
	return rep, nil
}

// Repair regenerates missing shards for every chunk that is still recoverable
// (>= K shards present), restoring each to full redundancy. Chunks that have
// dropped below K are unrecoverable; Repair reports them via a joined error but
// still repairs every other chunk. It returns a fresh Report reflecting the
// post-repair state.
func Repair(ctx context.Context, s store.Store, m pipeline.FileManifest) (Report, error) {
	p := m.Params.Params
	var errs []error
	for i, ref := range m.Chunks {
		if err := repairChunk(ctx, s, p, i, ref); err != nil {
			errs = append(errs, err)
		}
	}
	rep, err := Check(ctx, s, m)
	if err != nil {
		errs = append(errs, err)
	}
	return rep, errors.Join(errs...)
}

func repairChunk(ctx context.Context, s store.Store, p erasure.Params, idx int, ref pipeline.ChunkRef) error {
	// Fetch whatever survives, recording which positions are missing BEFORE we
	// decode (Reed–Solomon reconstruction fills the gaps in `shards` in place,
	// so we cannot infer the missing set from it afterwards).
	shards := make([][]byte, len(ref.Shards))
	var missing []int
	for pos, id := range ref.Shards {
		data, err := s.Get(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrCorrupt) {
				missing = append(missing, pos)
				continue
			}
			return fmt.Errorf("repair: chunk %d get shard %d: %w", idx, pos, err)
		}
		shards[pos] = data
	}
	if len(missing) == 0 {
		return nil // already whole
	}
	present := len(ref.Shards) - len(missing)
	if present < p.K {
		return fmt.Errorf("repair: chunk %d unrecoverable: %d of %d shards present, need %d",
			idx, present, len(ref.Shards), p.K)
	}

	// Recover the (still-encrypted) payload and deterministically re-encode.
	// Because Encode is deterministic, the regenerated shards reproduce the
	// original content addresses recorded in the manifest.
	sealed, err := erasure.Decode(p, shards)
	if err != nil {
		return fmt.Errorf("repair: chunk %d decode: %w", idx, err)
	}
	regen, err := erasure.Encode(p, sealed)
	if err != nil {
		return fmt.Errorf("repair: chunk %d re-encode: %w", idx, err)
	}
	for _, pos := range missing {
		want := ref.Shards[pos]
		got, err := s.Put(ctx, regen[pos])
		if err != nil {
			return fmt.Errorf("repair: chunk %d put shard %d: %w", idx, pos, err)
		}
		if got != want {
			return fmt.Errorf("repair: chunk %d shard %d regenerated to %s, want %s (non-deterministic encode?)",
				idx, pos, got, want)
		}
	}
	return nil
}
