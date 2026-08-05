package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"revika/internal/cap"
	"revika/internal/crypto"
	"revika/internal/manifest"
	"revika/internal/store"
)

// signRoot builds a signed RootPointer at seq over a small deterministic cap.
func signRoot(t *testing.T, k cap.SignKey, seq uint64) manifest.RootPointer {
	t.Helper()
	c := manifest.ReadCap{
		Kind:   manifest.KindDir,
		Key:    crypto.Key{1, 2, 3},
		K:      4,
		M:      2,
		Shards: []store.ShardID{{0xAA}, {0xBB}},
	}
	// The timestamp is caller-supplied (the manifest package takes no clock); a
	// fixed value keeps the test deterministic.
	rp, err := manifest.SignRoot(k, c, seq, int64(seq)*1000)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	return rp
}

func TestFileRootStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	k, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sub", "root.json") // sub/ must be created by Save
	frs := NewFileRootStore(path)

	// A fresh namespace: nothing stored yet.
	if _, ok, err := frs.Load(ctx); err != nil || ok {
		t.Fatalf("fresh Load: ok=%v err=%v (want ok=false, nil)", ok, err)
	}

	rp := signRoot(t, k, 1)
	if err := frs.Save(ctx, rp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := frs.Load(ctx)
	if err != nil || !ok {
		t.Fatalf("Load after Save: ok=%v err=%v", ok, err)
	}
	if got.Owner != rp.Owner || got.Seq != rp.Seq || got.Root.Kind != rp.Root.Kind || len(got.Root.Shards) != len(rp.Root.Shards) {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, rp)
	}
	if !got.Verify() {
		t.Fatal("loaded pointer failed signature verification")
	}

	// The file is written with owner-only permissions (SC-28).
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("root file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestFileRootStoreAntiRollback(t *testing.T) {
	ctx := context.Background()
	k, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	frs := NewFileRootStore(filepath.Join(t.TempDir(), "root.json"))

	if err := frs.Save(ctx, signRoot(t, k, 5)); err != nil {
		t.Fatalf("Save seq 5: %v", err)
	}
	// A lower or equal Seq must be refused (anti-rollback, SC-8).
	if err := frs.Save(ctx, signRoot(t, k, 5)); err == nil {
		t.Fatal("Save accepted a non-advancing seq (equal)")
	}
	if err := frs.Save(ctx, signRoot(t, k, 4)); err == nil {
		t.Fatal("Save accepted a rolled-back seq (lower)")
	}
	// A higher Seq advances the pointer.
	if err := frs.Save(ctx, signRoot(t, k, 6)); err != nil {
		t.Fatalf("Save seq 6: %v", err)
	}
	if got, _, _ := frs.Load(ctx); got.Seq != 6 {
		t.Fatalf("stored seq = %d, want 6", got.Seq)
	}
}

func TestFileRootStoreRejectsForeignOwner(t *testing.T) {
	ctx := context.Background()
	k1, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	frs := NewFileRootStore(filepath.Join(t.TempDir(), "root.json"))

	if err := frs.Save(ctx, signRoot(t, k1, 1)); err != nil {
		t.Fatalf("Save owner1: %v", err)
	}
	// A different identity cannot overwrite the stored pointer even with a higher
	// Seq — the store belongs to one owner.
	if err := frs.Save(ctx, signRoot(t, k2, 2)); err == nil {
		t.Fatal("Save accepted a pointer signed by a different owner")
	}
}

func TestFileRootStoreRejectsTamperedFile(t *testing.T) {
	ctx := context.Background()
	k, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.json")
	frs := NewFileRootStore(path)
	if err := frs.Save(ctx, signRoot(t, k, 1)); err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the signature region: Load must reject it rather than treat a
	// corrupt pointer as a fresh namespace.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := DecodeRootPointer(data)
	if err != nil {
		t.Fatal(err)
	}
	rp.Sig[0] ^= 0xFF
	bad, err := EncodeRootPointer(rp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := frs.Load(ctx); err == nil {
		t.Fatal("Load accepted a tampered root pointer")
	}
}

func TestDecodeRootPointerRejectsGarbage(t *testing.T) {
	if _, err := DecodeRootPointer([]byte("not json")); err == nil {
		t.Fatal("DecodeRootPointer accepted non-JSON")
	}
	if _, err := DecodeRootPointer([]byte(`{"owner":"!!","root":{},"seq":1}`)); err == nil {
		t.Fatal("DecodeRootPointer accepted a malformed owner key")
	}
}
