package pipeline

import (
	"bytes"
	"context"
	"math/rand"
	"testing"

	"revika/internal/erasure"
	"revika/internal/store"
)

// newStores returns the store implementations every pipeline test runs against.
func newStores(t *testing.T) map[string]store.Store {
	disk, err := store.NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	return map[string]store.Store{
		"mem":  store.NewMemStore(),
		"disk": disk,
	}
}

func testConfig() Config {
	// Small chunks so multi-chunk paths are exercised without large data.
	return Config{ChunkSize: 1024, Params: erasure.Params{K: 4, M: 2}}
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	sizes := []int{0, 1, 1023, 1024, 1025, 4096, 5000, 1 << 20}
	for name, s := range newStores(t) {
		for _, n := range sizes {
			data := randBytes(n, int64(n)+1)
			m, err := StoreFile(ctx, s, testConfig(), bytes.NewReader(data))
			if err != nil {
				t.Fatalf("[%s] StoreFile(%d): %v", name, n, err)
			}
			if m.Size != int64(n) {
				t.Fatalf("[%s] manifest size = %d, want %d", name, m.Size, n)
			}
			var out bytes.Buffer
			if err := LoadFile(ctx, s, m, &out); err != nil {
				t.Fatalf("[%s] LoadFile(%d): %v", name, n, err)
			}
			if !bytes.Equal(out.Bytes(), data) {
				t.Fatalf("[%s] round trip mismatch at size %d", name, n)
			}
		}
	}
}

// TestResilientToShardLoss deletes up to M shards per chunk and confirms the
// file still reconstructs; deleting M+1 makes a chunk unrecoverable.
func TestResilientToShardLoss(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()
	data := randBytes(5000, 99) // spans several 1 KiB chunks

	for name, s := range newStores(t) {
		m, err := StoreFile(ctx, s, cfg, bytes.NewReader(data))
		if err != nil {
			t.Fatalf("[%s] StoreFile: %v", name, err)
		}

		// Delete exactly M shards from every chunk → still recoverable.
		survivable := cloneManifest(m)
		rng := rand.New(rand.NewSource(3))
		for _, ref := range survivable.Chunks {
			for _, idx := range rng.Perm(len(ref.Shards))[:cfg.Params.M] {
				_ = s.Delete(ctx, ref.Shards[idx])
			}
		}
		var out bytes.Buffer
		if err := LoadFile(ctx, s, survivable, &out); err != nil {
			t.Fatalf("[%s] LoadFile after losing M shards: %v", name, err)
		}
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("[%s] data mismatch after losing M shards", name)
		}

		// Delete one more shard from the first chunk → unrecoverable.
		ref := m.Chunks[0]
		// Delete M+1 distinct shards of chunk 0.
		for _, idx := range rand.New(rand.NewSource(4)).Perm(len(ref.Shards))[:cfg.Params.M+1] {
			_ = s.Delete(ctx, ref.Shards[idx])
		}
		if err := LoadFile(ctx, s, m, &bytes.Buffer{}); err == nil {
			t.Fatalf("[%s] LoadFile should fail after losing M+1 shards", name)
		}
	}
}

func TestManifestChunkCount(t *testing.T) {
	ctx := context.Background()
	// 5000 bytes / 1024 = 5 chunks (4×1024 + 904).
	m, err := StoreFile(ctx, store.NewMemStore(), testConfig(), bytes.NewReader(randBytes(5000, 1)))
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	if len(m.Chunks) != 5 {
		t.Fatalf("got %d chunks, want 5", len(m.Chunks))
	}
	for i, ref := range m.Chunks {
		if len(ref.Shards) != testConfig().Params.N() {
			t.Fatalf("chunk %d: %d shards, want %d", i, len(ref.Shards), testConfig().Params.N())
		}
	}
}

// helpers

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func cloneManifest(m FileManifest) FileManifest {
	out := m
	out.Chunks = make([]ChunkRef, len(m.Chunks))
	for i, ref := range m.Chunks {
		cp := ref
		cp.Shards = append([]store.ShardID(nil), ref.Shards...)
		out.Chunks[i] = cp
	}
	return out
}
