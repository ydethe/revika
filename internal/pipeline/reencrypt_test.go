package pipeline

import (
	"bytes"
	"context"
	"testing"

	"revika/internal/store"
)

// TestReencryptFile checks the data-layer half of revocation: every chunk gets a
// fresh key and fresh shard IDs, yet the file reloads byte-for-byte, and the old
// shards survive for the caller to reclaim.
func TestReencryptFile(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	// Several chunks so the per-chunk rekey is exercised more than once.
	orig := randBytes(cfg.ChunkSize*3+123, 7)

	m, err := StoreFile(ctx, s, cfg, bytes.NewReader(orig))
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	rm, err := ReencryptFile(ctx, s, m)
	if err != nil {
		t.Fatalf("ReencryptFile: %v", err)
	}

	if len(rm.Chunks) != len(m.Chunks) {
		t.Fatalf("chunk count changed: %d → %d", len(m.Chunks), len(rm.Chunks))
	}
	if rm.Size != m.Size {
		t.Fatalf("size changed: %d → %d", m.Size, rm.Size)
	}

	// Every chunk's key and shard IDs must be fresh.
	oldIDs := map[store.ShardID]struct{}{}
	for _, ref := range m.Chunks {
		for _, id := range ref.Shards {
			oldIDs[id] = struct{}{}
		}
	}
	for i := range rm.Chunks {
		if rm.Chunks[i].Key == m.Chunks[i].Key {
			t.Fatalf("chunk %d reused its encryption key", i)
		}
		for _, id := range rm.Chunks[i].Shards {
			if _, ok := oldIDs[id]; ok {
				t.Fatalf("chunk %d reused old shard %s", i, id)
			}
		}
	}

	// The re-encrypted manifest reloads to the original bytes.
	var buf bytes.Buffer
	if err := LoadFile(ctx, s, rm, &buf); err != nil {
		t.Fatalf("LoadFile(reencrypted): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), orig) {
		t.Fatal("re-encrypted file does not reload to original bytes")
	}

	// The old shards were left in place (reclamation is the caller's job), so the
	// original manifest still reads too, until those shards are deleted.
	buf.Reset()
	if err := LoadFile(ctx, s, m, &buf); err != nil {
		t.Fatalf("LoadFile(original) after reencrypt: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), orig) {
		t.Fatal("original manifest no longer reads after reencrypt")
	}
}
