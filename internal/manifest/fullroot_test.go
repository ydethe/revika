package manifest

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"revika/internal/cap"
	"revika/internal/store"
)

// TestSealFullRootRoundTrip is the Stage-0 crux: device A seals its full root
// (key retained) to the owner's own ML-KEM key; device B (same shared owner keys)
// opens it and reads back a blob the public verify-root could never decrypt.
func TestSealFullRootRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()

	// Owner keys, shared by every device: one ML-KEM pair + one Ed25519 pair.
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// Device A builds a namespace and seals the full root at seq 3.
	root, _, oldA := buildTree(t, ctx, s, cfg)
	want := loadFile(t, ctx, s, oldA)

	rec, err := SealFullRoot(sk, pub, root, 3)
	if err != nil {
		t.Fatalf("SealFullRoot: %v", err)
	}
	if rec.Owner != owner || rec.Seq != 3 {
		t.Fatalf("record owner/seq: owner-match=%v seq=%d", rec.Owner == owner, rec.Seq)
	}
	if !rec.Verify() {
		t.Fatal("freshly sealed record should verify")
	}

	// Device B opens it with the shared owner keys and recovers the full cap.
	got, err := rec.Open(priv, pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !reflect.DeepEqual(got, root) {
		t.Fatal("opened full root cap differs from the sealed one (key or locators lost)")
	}

	// And the recovered cap actually decrypts content — the whole point of the
	// companion vs the key-stripped verify-root.
	a, err := Resolve(ctx, s, got, "docs/a.txt")
	if err != nil {
		t.Fatalf("Resolve via opened root: %v", err)
	}
	if gotBytes := loadFile(t, ctx, s, a); !bytes.Equal(gotBytes, want) {
		t.Fatal("blob read via opened full root does not match original bytes")
	}
}

// TestFullRootTamperRejected checks the signature binds the sealed bytes and
// seq: mutating either after signing fails Verify (and thus Open).
func TestFullRootTamperRejected(t *testing.T) {
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	root := ReadCap{Kind: KindDir, K: 4, M: 2, Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}}}
	rec, err := SealFullRoot(sk, pub, root, 1)
	if err != nil {
		t.Fatalf("SealFullRoot: %v", err)
	}

	bad := rec
	bad.Seq = 99 // changes signed bytes without re-signing
	if bad.Verify() {
		t.Fatal("seq tamper should fail verification")
	}

	bad = rec
	bad.Sealed = append([]byte(nil), rec.Sealed...)
	bad.Sealed[0] ^= 0xFF
	if bad.Verify() {
		t.Fatal("sealed-byte tamper should fail verification")
	}
	if _, err := bad.Open(priv, pub); err == nil {
		t.Fatal("Open on a tampered record should error")
	}
}
