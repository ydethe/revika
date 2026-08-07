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

// TestSealFullRootForMultiDevice is the read-side device-revocation crux
// (Architecture §3.7.2): the full root is sealed to three devices at once; each
// authorized device opens it with its own ML-KEM key, and a non-listed (revoked)
// device's key opens nothing.
func TestSealFullRootForMultiDevice(t *testing.T) {
	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	// Three authorized devices + one that is not in the set (stands in for a
	// revoked device).
	type dev struct {
		priv cap.PrivateKey
		pub  cap.PublicKey
	}
	var devs []dev
	for range 3 {
		priv, pub, err := cap.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		devs = append(devs, dev{priv, pub})
	}
	outPriv, outPub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	root := ReadCap{Kind: KindDir, K: 4, M: 2, Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}}}
	root.Key[0] = 0x7e

	recipients := []cap.PublicKey{devs[0].pub, devs[1].pub, devs[2].pub}
	rec, err := SealFullRootFor(sk, recipients, root, 5)
	if err != nil {
		t.Fatalf("SealFullRootFor: %v", err)
	}
	if rec.Owner != owner || rec.Seq != 5 {
		t.Fatalf("record owner/seq wrong: owner-match=%v seq=%d", rec.Owner == owner, rec.Seq)
	}
	if len(rec.Sealed) != 0 {
		t.Fatal("device-scoped record should leave the legacy Sealed empty")
	}
	if len(rec.Seals) != 3 {
		t.Fatalf("Seals len = %d, want 3", len(rec.Seals))
	}
	if !rec.Verify() {
		t.Fatal("device-scoped record failed Verify")
	}

	// Every authorized device opens it and recovers the identical key-bearing cap.
	for i, d := range devs {
		got, err := rec.Open(d.priv, d.pub)
		if err != nil {
			t.Fatalf("device %d Open: %v", i, err)
		}
		if !reflect.DeepEqual(got, root) {
			t.Fatalf("device %d opened a different cap", i)
		}
	}

	// A device not in the set (revoked / never enrolled) opens nothing.
	if _, err := rec.Open(outPriv, outPub); err == nil {
		t.Fatal("a non-recipient device should not be able to open the companion")
	}

	// Read revocation: re-seal to the survivors only (drop devs[0]); the dropped
	// device can no longer open the new record, the survivors still can.
	survivors := []cap.PublicKey{devs[1].pub, devs[2].pub}
	rec2, err := SealFullRootFor(sk, survivors, root, 6)
	if err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if _, err := rec2.Open(devs[0].priv, devs[0].pub); err == nil {
		t.Fatal("revoked device still opened the re-sealed companion")
	}
	if _, err := rec2.Open(devs[1].priv, devs[1].pub); err != nil {
		t.Fatalf("survivor lost access after revoke: %v", err)
	}

	// Empty recipient set is rejected rather than producing an unopenable record.
	if _, err := SealFullRootFor(sk, nil, root, 7); err == nil {
		t.Fatal("SealFullRootFor with no recipients should error")
	}
}

// TestFullRootSealTamperRejected checks the signature also binds the multi-device
// Seals list: mutating any seal after signing fails Verify.
func TestFullRootSealTamperRejected(t *testing.T) {
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := ReadCap{Kind: KindDir, K: 4, M: 2, Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}}}
	rec, err := SealFullRootFor(sk, []cap.PublicKey{pub}, root, 1)
	if err != nil {
		t.Fatalf("SealFullRootFor: %v", err)
	}
	bad := rec
	bad.Seals = [][]byte{append([]byte(nil), rec.Seals[0]...)}
	bad.Seals[0][0] ^= 0xFF
	if bad.Verify() {
		t.Fatal("seal-byte tamper should fail verification")
	}
	// A well-formed but signature-less record must not open.
	if _, err := (FullRootRecord{Owner: rec.Owner, Seq: 1, Seals: rec.Seals}).Open(priv, pub); err == nil {
		t.Fatal("unsigned record should not open")
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
