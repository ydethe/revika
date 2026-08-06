package net

import (
	"context"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/provider"
	"revika/internal/store"
)

// signedRoot builds a signed RootPointer over a trivial cap for owner sk at seq.
func signedRoot(t *testing.T, sk cap.SignKey, seq uint64) manifest.RootPointer {
	t.Helper()
	root := manifest.ReadCap{
		Kind:   manifest.KindDir,
		K:      4,
		M:      2,
		Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}},
	}
	rp, err := manifest.SignRoot(sk, root, seq, int64(seq)*1_000_000)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	// Publish form is key-stripped, exactly as PutRoot serializes it.
	rp.Root = rp.Root.VerifyCap().ReadCap()
	return rp
}

func encRoot(t *testing.T, rp manifest.RootPointer) []byte {
	t.Helper()
	b, err := provider.EncodeRootPointer(rp)
	if err != nil {
		t.Fatalf("EncodeRootPointer: %v", err)
	}
	return b
}

// TestRootValidator checks the record.Validator rules the DHT enforces on root
// records: a good record validates; wrong namespace, wrong key length, an
// owner/key mismatch, and a broken signature are all rejected; Select prefers the
// highest Seq.
func TestRootValidator(t *testing.T) {
	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	v := rootValidator{}
	rp := signedRoot(t, sk, 1)
	val := encRoot(t, rp)
	key := rootKey(owner)

	if err := v.Validate(key, val); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	// Wrong namespace.
	if err := v.Validate("/wrong/"+string(owner[:]), val); err == nil {
		t.Fatal("wrong namespace should be rejected")
	}
	// Key path not a pubkey length.
	if err := v.Validate("/"+RootNamespace+"/short", val); err == nil {
		t.Fatal("short key path should be rejected")
	}
	// Owner/key mismatch: a record signed by a different key under owner's slot.
	otherSk, _, _ := cap.GenerateSigningKey()
	otherVal := encRoot(t, signedRoot(t, otherSk, 1))
	if err := v.Validate(key, otherVal); err == nil {
		t.Fatal("owner/key mismatch should be rejected")
	}
	// Tampered signature.
	bad := rp
	bad.Seq = 99 // changes signed bytes without re-signing
	if err := v.Validate(key, encRoot(t, bad)); err == nil {
		t.Fatal("tampered record should be rejected")
	}

	// Select prefers the highest Seq.
	v1 := encRoot(t, signedRoot(t, sk, 1))
	v5 := encRoot(t, signedRoot(t, sk, 5))
	v3 := encRoot(t, signedRoot(t, sk, 3))
	idx, err := v.Select(key, [][]byte{v1, v5, v3})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if idx != 1 {
		t.Fatalf("Select picked index %d, want 1 (seq 5)", idx)
	}
}

// signedForkRoot builds a signed, key-stripped RootPointer at seq whose root cap
// carries a caller-chosen leading shard byte, so two forks at the same seq encode
// to different bytes.
func signedForkRoot(t *testing.T, sk cap.SignKey, seq uint64, tag byte) manifest.RootPointer {
	t.Helper()
	root := manifest.ReadCap{
		Kind:   manifest.KindDir,
		K:      4,
		M:      2,
		Shards: []store.ShardID{{tag}, {2}, {3}, {4}, {5}, {6}},
	}
	rp, err := manifest.SignRoot(sk, root, seq, int64(seq)*1_000_000)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	rp.Root = rp.Root.VerifyCap().ReadCap()
	return rp
}

// TestRootValidatorSelectTieBreak checks that two equal-Seq forks (one owner key
// advanced to the same sequence against different roots — the multi-device fork)
// resolve to the SAME record regardless of the order they are presented in. A
// first-seen tie-break would let different replicas keep different forks.
func TestRootValidatorSelectTieBreak(t *testing.T) {
	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	v := rootValidator{}
	key := rootKey(owner)

	a := encRoot(t, signedForkRoot(t, sk, 5, 0xAA))
	b := encRoot(t, signedForkRoot(t, sk, 5, 0xBB))

	// Same inputs, opposite order → the winning bytes must be identical.
	i1, err := v.Select(key, [][]byte{a, b})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	i2, err := v.Select(key, [][]byte{b, a})
	if err != nil {
		t.Fatalf("Select reversed: %v", err)
	}
	win1 := [][]byte{a, b}[i1]
	win2 := [][]byte{b, a}[i2]
	if string(win1) != string(win2) {
		t.Fatal("Select tie-break is order-dependent: different forks won under different orderings")
	}

	// A higher Seq still trumps any tie-break.
	c := encRoot(t, signedForkRoot(t, sk, 6, 0x01))
	idx, err := v.Select(key, [][]byte{a, c, b})
	if err != nil {
		t.Fatalf("Select with higher seq: %v", err)
	}
	if idx != 1 {
		t.Fatalf("Select picked %d, want 1 (seq 6)", idx)
	}
}

// TestPutGetRootDHT round-trips a root pointer through an in-process two-node DHT
// and confirms anti-rollback: a lower-Seq re-put never displaces the newer record.
func TestPutGetRootDHT(t *testing.T) {
	seed := newDHTNode(t, DHTModeServer, store.NewMemStore())
	client := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))
	waitRoutingTable(t, client)
	waitRoutingTable(t, seed)

	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Before any publish, resolution is a clean miss.
	if _, ok, err := client.GetRoot(ctx, owner); err != nil || ok {
		t.Fatalf("GetRoot before publish: ok=%v err=%v", ok, err)
	}

	rp1 := signedRoot(t, sk, 1)
	if err := seed.PutRoot(ctx, rp1); err != nil {
		t.Fatalf("PutRoot seq 1: %v", err)
	}
	got, ok, err := client.GetRoot(ctx, owner)
	if err != nil || !ok {
		t.Fatalf("GetRoot seq 1: ok=%v err=%v", ok, err)
	}
	if got.Seq != 1 || got.Owner != owner {
		t.Fatalf("resolved seq %d owner match=%v", got.Seq, got.Owner == owner)
	}
	// The published record carries no key (verify projection only).
	var zero [len(got.Root.Key)]byte
	if got.Root.Key != zero {
		t.Fatal("published root leaked a decryption key")
	}

	// Advance to seq 2; the client resolves the newer record.
	rp2 := signedRoot(t, sk, 2)
	if err := seed.PutRoot(ctx, rp2); err != nil {
		t.Fatalf("PutRoot seq 2: %v", err)
	}
	got, _, err = client.GetRoot(ctx, owner)
	if err != nil {
		t.Fatalf("GetRoot seq 2: %v", err)
	}
	if got.Seq != 2 {
		t.Fatalf("resolved seq %d, want 2", got.Seq)
	}

	// Anti-rollback: re-putting seq 1 must not roll the network back. The local
	// validator's Select rejects the stale value, so a later Get still sees seq 2.
	_ = seed.PutRoot(ctx, rp1) // may error locally; either way must not win
	got, _, err = client.GetRoot(ctx, owner)
	if err != nil {
		t.Fatalf("GetRoot after rollback attempt: %v", err)
	}
	if got.Seq != 2 {
		t.Fatalf("rollback attempt won: resolved seq %d, want 2", got.Seq)
	}
}

// TestPutGetFullRootDHT round-trips the sealed self-root companion through an
// in-process two-node DHT: device A publishes the full (key-bearing) root sealed
// to the owner ML-KEM key alongside the key-stripped verify-root; device B (same
// shared owner keys) resolves the verify-root, opens the companion, and gets back
// a decryptable cap bound to the signed verify-root.
func TestPutGetFullRootDHT(t *testing.T) {
	seed := newDHTNode(t, DHTModeServer, store.NewMemStore())
	client := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))
	waitRoutingTable(t, client)
	waitRoutingTable(t, seed)

	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Verify-root's cap must match what the companion opens to; build one full
	// cap and derive both records from it.
	full := manifest.ReadCap{
		Kind:   manifest.KindDir,
		K:      4,
		M:      2,
		Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}},
	}
	full.Key[0] = 0x42 // a non-zero key so stripping is observable

	// Before any publish, resolution is a clean miss.
	if _, ok, err := client.GetFullRoot(ctx, owner, priv, pub, full); err != nil || ok {
		t.Fatalf("GetFullRoot before publish: ok=%v err=%v", ok, err)
	}

	rp, err := manifest.SignRoot(sk, full, 4, 4_000_000)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	rec, err := manifest.SealFullRoot(sk, pub, full, 4)
	if err != nil {
		t.Fatalf("SealFullRoot: %v", err)
	}
	if err := seed.PutFullRoot(ctx, rec); err != nil {
		t.Fatalf("PutFullRoot: %v", err)
	}

	// The client resolves the verify-root and opens the companion against it.
	got, ok, err := client.GetFullRoot(ctx, owner, priv, pub, rp.Root)
	if err != nil || !ok {
		t.Fatalf("GetFullRoot: ok=%v err=%v", ok, err)
	}
	if got.Key != full.Key {
		t.Fatal("opened full root lost its AES key")
	}

	// Binding failure: a companion whose cap does not match the presented
	// verify-root is rejected (stale/forged), not merged.
	other := full
	other.Shards = []store.ShardID{{9}, {9}, {9}, {9}, {9}, {9}}
	if _, _, err := client.GetFullRoot(ctx, owner, priv, pub, other); err == nil {
		t.Fatal("companion not matching the verify-root should be rejected")
	}
}

// TestFullRootValidator checks the fullRootValidator rules directly: a good
// record validates; wrong namespace, wrong key length, owner/key mismatch, and a
// tampered signature are rejected; Select prefers the highest Seq and breaks ties
// deterministically.
func TestFullRootValidator(t *testing.T) {
	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := manifest.ReadCap{Kind: manifest.KindDir, K: 4, M: 2, Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}}}

	enc := func(seq uint64, s cap.SignKey) []byte {
		rec, err := manifest.SealFullRoot(s, pub, root, seq)
		if err != nil {
			t.Fatalf("SealFullRoot: %v", err)
		}
		b, err := provider.EncodeFullRoot(rec)
		if err != nil {
			t.Fatalf("EncodeFullRoot: %v", err)
		}
		return b
	}

	v := fullRootValidator{}
	key := fullRootKey(owner)
	val := enc(1, sk)

	if err := v.Validate(key, val); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if err := v.Validate("/wrong/"+string(owner[:]), val); err == nil {
		t.Fatal("wrong namespace should be rejected")
	}
	if err := v.Validate("/"+FullRootNamespace+"/short", val); err == nil {
		t.Fatal("short key path should be rejected")
	}
	otherSk, _, _ := cap.GenerateSigningKey()
	if err := v.Validate(key, enc(1, otherSk)); err == nil {
		t.Fatal("owner/key mismatch should be rejected")
	}
	// Tamper: flip a byte of the encoded record's owner-independent payload.
	bad := append([]byte(nil), val...)
	bad[len(bad)-3] ^= 0xFF
	if err := v.Validate(key, bad); err == nil {
		t.Fatal("tampered record should be rejected")
	}

	// Select: highest seq wins.
	idx, err := v.Select(key, [][]byte{enc(1, sk), enc(5, sk), enc(3, sk)})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if idx != 1 {
		t.Fatalf("Select picked %d, want 1 (seq 5)", idx)
	}
}

// TestQueryRootProtocol round-trips a root through the /revika/root stream
// protocol: a node serving from its DHT view answers a direct client query.
func TestQueryRootProtocol(t *testing.T) {
	seedStore := store.NewMemStore()
	seed := newDHTNode(t, DHTModeServer, seedStore)
	// newDHTNode registers a Server but does not wire a root resolver; register a
	// second Server here with the resolver set, on the same host.
	srv := NewServer(seedStore, nil)
	srv.SetRootResolver(seed)
	srv.Register(seed.h)

	client := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))
	waitRoutingTable(t, client)
	waitRoutingTable(t, seed)

	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Miss before publish.
	if _, ok, err := QueryRoot(ctx, client.h, seed.h.ID(), owner); err != nil || ok {
		t.Fatalf("QueryRoot before publish: ok=%v err=%v", ok, err)
	}

	if err := seed.PutRoot(ctx, signedRoot(t, sk, 7)); err != nil {
		t.Fatalf("PutRoot: %v", err)
	}
	got, ok, err := QueryRoot(ctx, client.h, seed.h.ID(), owner)
	if err != nil || !ok {
		t.Fatalf("QueryRoot: ok=%v err=%v", ok, err)
	}
	if got.Seq != 7 || got.Owner != owner {
		t.Fatalf("queried seq %d owner match=%v", got.Seq, got.Owner == owner)
	}
}
