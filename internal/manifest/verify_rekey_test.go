package manifest

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"revika/internal/cap"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// collectShards walks the DAG rooted at c and returns the set of every shard ID
// reachable — the manifest/dir blob shards and, for files, the data-chunk
// shards. It is the test's stand-in for the reclamation walk revika-ctl does.
func collectShards(t *testing.T, ctx context.Context, s store.Store, c ReadCap) map[store.ShardID]struct{} {
	t.Helper()
	out := map[store.ShardID]struct{}{}
	var walk func(c ReadCap)
	walk = func(c ReadCap) {
		for _, id := range c.Shards {
			out[id] = struct{}{}
		}
		switch c.Kind {
		case KindFile:
			fm, err := LoadFileManifest(ctx, s, c)
			if err != nil {
				t.Fatalf("LoadFileManifest: %v", err)
			}
			for _, ch := range fm.Chunks {
				for _, id := range ch.Shards {
					out[id] = struct{}{}
				}
			}
		case KindDir:
			d, err := LoadDir(ctx, s, c)
			if err != nil {
				t.Fatalf("LoadDir: %v", err)
			}
			for _, e := range d.Entries {
				walk(e.Cap)
			}
		}
	}
	walk(c)
	return out
}

// TestVerifyCapRoundTrip checks the downward derivation ReadCap→VerifyCap→ReadCap:
// the projection drops only the AES key, keeps every locator/param, and the
// re-embedded ReadCap serializes with an all-zero key.
func TestVerifyCapRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	full := storeFile(t, ctx, s, cfg, "f.txt", bytes.Repeat([]byte("x"), 5000))

	v := full.VerifyCap()
	if v.Kind != full.Kind || v.K != full.K || v.M != full.M || v.Compressed != full.Compressed {
		t.Fatal("VerifyCap dropped a non-key field")
	}
	if !reflect.DeepEqual(v.Shards, full.Shards) {
		t.Fatal("VerifyCap changed the shard list")
	}

	// Re-embedding yields a ReadCap identical to the original save its zeroed key.
	back := v.ReadCap()
	var zero [len(back.Key)]byte
	if !bytes.Equal(back.Key[:], zero[:]) {
		t.Fatal("VerifyCap.ReadCap() must carry a zero key")
	}
	want := full
	want.Key = back.Key // only the key differs
	if !reflect.DeepEqual(back, want) {
		t.Fatal("VerifyCap.ReadCap() differs from the original beyond its key")
	}

	// The zero-key form marshals and round-trips through the JSON codec cleanly.
	raw, err := back.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal stripped cap: %v", err)
	}
	var reparsed ReadCap
	if err := reparsed.UnmarshalBinary(raw); err != nil {
		t.Fatalf("unmarshal stripped cap: %v", err)
	}
	if !reflect.DeepEqual(reparsed, back) {
		t.Fatal("stripped cap did not round-trip through JSON")
	}
}

// TestRootPointerVerifyProjection is the linchpin: a full-cap pointer (local root
// file, key retained) and its key-stripped projection (the DHT form) both verify
// under the *same* signature, because the signed payload commits to the verify
// projection only.
func TestRootPointerVerifyProjection(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, _, _ := buildTree(t, ctx, s, cfg)

	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	full, err := SignRoot(sk, root, 1, 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	if !full.Verify() {
		t.Fatal("full-cap pointer should verify")
	}

	// Strip the key exactly as PutRoot does before publishing, reusing the same
	// signature — it must still verify.
	stripped := full
	stripped.Root = full.Root.VerifyCap().ReadCap()
	if bytes.Equal(stripped.Root.Key[:], full.Root.Key[:]) {
		t.Fatal("stripping did not remove the key (test tree may be trivially keyed)")
	}
	if !stripped.Verify() {
		t.Fatal("key-stripped pointer must verify under the same signature")
	}
	if !bytes.Equal(stripped.Sig, full.Sig) {
		t.Fatal("stripping must not require re-signing")
	}

	// Tampering with a *signed* field of the stripped form (a shard ID) breaks it.
	bad := stripped
	bad.Root.Shards = append([]store.ShardID(nil), stripped.Root.Shards...)
	bad.Root.Shards[0] = store.ShardID{}
	if bad.Verify() {
		t.Fatal("altered shard ID should not verify")
	}
}

// TestVerifyBlob confirms a VerifyCap attests availability without a key, and
// reports unrecoverable once fewer than K shards remain.
func TestVerifyBlob(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	// A directory blob is a single stripe of K+M shards — easy to knock out.
	dirCap := mustStoreDir(t, ctx, s, cfg, NewDir(pipeline.Metadata{}))

	v := dirCap.VerifyCap()
	if err := VerifyBlob(ctx, s, v); err != nil {
		t.Fatalf("intact blob should verify: %v", err)
	}

	// Delete M shards (parity margin) — still recoverable.
	for i := 0; i < v.M; i++ {
		if err := s.Delete(ctx, v.Shards[i]); err != nil {
			t.Fatalf("delete shard: %v", err)
		}
	}
	if err := VerifyBlob(ctx, s, v); err != nil {
		t.Fatalf("blob with M shards missing should still verify: %v", err)
	}
	// Drop one more — now below K, unrecoverable.
	if err := s.Delete(ctx, v.Shards[v.M]); err != nil {
		t.Fatalf("delete shard: %v", err)
	}
	if err := VerifyBlob(ctx, s, v); err == nil {
		t.Fatal("blob below K shards should fail verification")
	}
}

// TestRekeySubtree exercises revocation-by-rekey: rekeying /docs mints fresh shard
// IDs for every blob under it, leaves the sibling notes.txt byte-identical, still
// reads back the original plaintext, and the old (pre-rekey) cap can no longer be
// used to open the current bytes.
func TestRekeySubtree(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, notes, oldA := buildTree(t, ctx, s, cfg)

	oldSub, err := Resolve(ctx, s, root, "docs")
	if err != nil {
		t.Fatal(err)
	}
	oldShards := collectShards(t, ctx, s, oldSub)

	newRoot, err := Rekey(ctx, s, cfg, root, "docs")
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	// Every shard under the rekeyed subtree is a new content address.
	newSub, err := Resolve(ctx, s, newRoot, "docs")
	if err != nil {
		t.Fatal(err)
	}
	newShards := collectShards(t, ctx, s, newSub)
	for id := range newShards {
		if _, ok := oldShards[id]; ok {
			t.Fatalf("rekeyed subtree reused old shard %s", id)
		}
	}

	// The rekeyed file still decrypts to the original bytes under the new cap.
	newA, err := Resolve(ctx, s, newRoot, "docs/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := loadFile(t, ctx, s, newA); !bytes.Equal(got, bytes.Repeat([]byte("A"), 9000)) {
		t.Fatal("rekeyed a.txt does not reload to original content")
	}

	// The sibling notes.txt outside the subtree is untouched (same cap, same shards).
	sibNotes, err := Resolve(ctx, s, newRoot, "notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sibNotes, notes) {
		t.Fatal("sibling notes.txt cap changed across a subtree rekey")
	}

	// The old cap is now stale: its data shards were the ones we can delete to
	// simulate reclamation, after which it can no longer be read.
	keep := collectShards(t, ctx, s, newRoot)
	for id := range oldShards {
		if _, ok := keep[id]; ok {
			continue // content-shared with the live tree; never reclaim
		}
		if err := s.Delete(ctx, id); err != nil {
			t.Fatalf("reclaim old shard %s: %v", id, err)
		}
	}
	if err := loadFileErr(ctx, s, oldA); err == nil {
		t.Fatal("stale cap still reads after its shards were reclaimed")
	}
}

// loadFileErr attempts a full file read via the old cap and returns the error
// (nil on unexpected success).
func loadFileErr(ctx context.Context, s store.Store, c ReadCap) error {
	fm, err := LoadFileManifest(ctx, s, c)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	return pipeline.LoadFile(ctx, s, fm, &buf)
}
