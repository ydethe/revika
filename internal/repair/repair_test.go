package repair

import (
	"bytes"
	"context"
	"math/rand"
	"testing"

	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

func cfg() pipeline.Config {
	return pipeline.Config{ChunkSize: 1024, Params: erasure.Params{K: 4, M: 2}}
}

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func newStores(t *testing.T) map[string]store.Store {
	disk, err := store.NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	return map[string]store.Store{"mem": store.NewMemStore(), "disk": disk}
}

// storeFile writes random data and returns the manifest and the original bytes.
func storeFile(t *testing.T, s store.Store, n int, seed int64) (pipeline.FileManifest, []byte) {
	t.Helper()
	data := randBytes(n, seed)
	m, err := pipeline.StoreFile(context.Background(), s, cfg(), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	return m, data
}

func TestCheckHealthy(t *testing.T) {
	ctx := context.Background()
	for name, s := range newStores(t) {
		m, _ := storeFile(t, s, 5000, 1)
		rep, err := Check(ctx, s, m)
		if err != nil {
			t.Fatalf("[%s] Check: %v", name, err)
		}
		if !rep.Healthy() {
			t.Fatalf("[%s] fresh file should be healthy, missing %d", name, rep.MissingShards())
		}
	}
}

// TestRepairRestoresRedundancy is the core loop: lose shards → Check sees the
// deficit → Repair → Check healthy → data still reconstructs, and regenerated
// shard IDs are identical to the originals.
func TestRepairRestoresRedundancy(t *testing.T) {
	ctx := context.Background()
	for name, s := range newStores(t) {
		m, data := storeFile(t, s, 5000, 2)

		// Kill M shards from each chunk (recoverable but degraded).
		rng := rand.New(rand.NewSource(7))
		killed := 0
		for _, ref := range m.Chunks {
			for _, pos := range rng.Perm(len(ref.Shards))[:cfg().Params.M] {
				if err := s.Delete(ctx, ref.Shards[pos]); err == nil {
					killed++
				}
			}
		}

		before, _ := Check(ctx, s, m)
		if before.Healthy() {
			t.Fatalf("[%s] expected deficit after deleting %d shards", name, killed)
		}

		rep, err := Repair(ctx, s, m)
		if err != nil {
			t.Fatalf("[%s] Repair: %v", name, err)
		}
		if !rep.Healthy() {
			t.Fatalf("[%s] not healthy after repair: %d missing", name, rep.MissingShards())
		}

		// Every manifest shard ID must now be present (IDs unchanged).
		for ci, ref := range m.Chunks {
			for pos, id := range ref.Shards {
				if ok, _ := s.Has(ctx, id); !ok {
					t.Fatalf("[%s] chunk %d shard %d (%s) absent after repair", name, ci, pos, id)
				}
			}
		}

		// Data still reconstructs.
		var out bytes.Buffer
		if err := pipeline.LoadFile(ctx, s, m, &out); err != nil {
			t.Fatalf("[%s] LoadFile after repair: %v", name, err)
		}
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("[%s] data mismatch after repair", name)
		}
	}
}

func TestRepairHealthyIsNoOp(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	m, _ := storeFile(t, s, 3000, 3)
	rep, err := Repair(ctx, s, m)
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if !rep.Healthy() {
		t.Fatal("healthy file should stay healthy")
	}
}

// TestUnrecoverableChunkErrors: dropping M+1 shards from a chunk makes it
// unrepairable; Repair must report an error and must not fabricate bad shards.
func TestUnrecoverableChunkErrors(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	m, _ := storeFile(t, s, 1500, 4) // 2 chunks

	ref := m.Chunks[0]
	for _, pos := range rand.New(rand.NewSource(5)).Perm(len(ref.Shards))[:cfg().Params.M+1] {
		_ = s.Delete(ctx, ref.Shards[pos])
	}

	rep, err := Repair(ctx, s, m)
	if err == nil {
		t.Fatal("Repair of unrecoverable chunk should error")
	}
	// Chunk 0 is unrecoverable; chunk 1 (untouched) must remain healthy.
	if !rep.Chunks[1].Healthy() {
		t.Fatal("healthy chunk should be unaffected by another chunk's failure")
	}
	if rep.Chunks[0].Recoverable(cfg().Params.K) {
		t.Fatal("chunk 0 should be below K")
	}
}

// TestEndToEndStoreRepairLoad is the steps 1–6 capstone: a multi-MB file
// through the whole stack (chunk → encrypt → erasure-code → store), degraded
// past redundancy-margin-but-not-fatal, repaired, and read back byte-for-byte —
// on both the in-memory and on-disk stores.
func TestEndToEndStoreRepairLoad(t *testing.T) {
	ctx := context.Background()
	c := pipeline.Config{ChunkSize: 256 << 10, Params: erasure.Params{K: 4, M: 2}}
	data := randBytes(3<<20+777, 12345) // ~3 MiB, non-chunk-aligned

	for name, s := range newStores(t) {
		m, err := pipeline.StoreFile(ctx, s, c, bytes.NewReader(data))
		if err != nil {
			t.Fatalf("[%s] StoreFile: %v", name, err)
		}
		if !mustCheck(t, s, m).Healthy() {
			t.Fatalf("[%s] fresh file not healthy", name)
		}

		// Kill M shards from every chunk: degraded but recoverable everywhere.
		rng := rand.New(rand.NewSource(2024))
		for _, ref := range m.Chunks {
			for _, pos := range rng.Perm(len(ref.Shards))[:c.Params.M] {
				_ = s.Delete(ctx, ref.Shards[pos])
			}
		}
		if mustCheck(t, s, m).Healthy() {
			t.Fatalf("[%s] expected degradation after shard deletion", name)
		}

		rep, err := Repair(ctx, s, m)
		if err != nil {
			t.Fatalf("[%s] Repair: %v", name, err)
		}
		if !rep.Healthy() {
			t.Fatalf("[%s] not healthy after repair: %d missing", name, rep.MissingShards())
		}

		var out bytes.Buffer
		if err := pipeline.LoadFile(ctx, s, m, &out); err != nil {
			t.Fatalf("[%s] LoadFile: %v", name, err)
		}
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("[%s] final data mismatch", name)
		}
	}
}

func mustCheck(t *testing.T, s store.Store, m pipeline.FileManifest) Report {
	t.Helper()
	rep, err := Check(context.Background(), s, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return rep
}

// TestRepairIsIdempotent: repairing twice changes nothing the second time.
func TestRepairIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	m, data := storeFile(t, s, 4096, 6)

	_ = s.Delete(ctx, m.Chunks[0].Shards[0])
	if _, err := Repair(ctx, s, m); err != nil {
		t.Fatalf("first Repair: %v", err)
	}
	rep, err := Repair(ctx, s, m)
	if err != nil {
		t.Fatalf("second Repair: %v", err)
	}
	if !rep.Healthy() {
		t.Fatal("should be healthy after idempotent repair")
	}
	var out bytes.Buffer
	if err := pipeline.LoadFile(ctx, s, m, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("data broken after double repair: err=%v", err)
	}
}
