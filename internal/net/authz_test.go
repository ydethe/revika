package net

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
)

// --- token unit tests -----------------------------------------------------

func TestTokenRoundTrip(t *testing.T) {
	signer, pub, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	node := peer.ID("node-A")
	shard := store.HashOf([]byte("some shard"))
	now := time.Unix(1_700_000_000, 0)

	tok := buildToken(signer, opPut, shard, node, now.Unix())
	owner, err := verifyToken(tok, opPut, shard, node, now)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if !bytes.Equal(owner, pub[:]) {
		t.Fatalf("owner = %x, want %x", owner, pub[:])
	}
}

func TestTokenRejections(t *testing.T) {
	signer, _, _ := cap.GenerateSigningKey()
	node := peer.ID("node-A")
	shard := store.HashOf([]byte("some shard"))
	now := time.Unix(1_700_000_000, 0)
	tok := buildToken(signer, opPut, shard, node, now.Unix())

	cases := []struct {
		name string
		run  func() ([]byte, error)
	}{
		{"wrong node", func() ([]byte, error) { return verifyToken(tok, opPut, shard, peer.ID("node-B"), now) }},
		{"wrong op", func() ([]byte, error) { return verifyToken(tok, opDelete, shard, node, now) }},
		{"wrong shard", func() ([]byte, error) {
			return verifyToken(tok, opPut, store.HashOf([]byte("other")), node, now)
		}},
		{"stale timestamp", func() ([]byte, error) {
			return verifyToken(tok, opPut, shard, node, now.Add(time.Hour))
		}},
		{"empty token", func() ([]byte, error) { return verifyToken(nil, opPut, shard, node, now) }},
		{"tampered signature", func() ([]byte, error) {
			bad := append([]byte(nil), tok...)
			bad[len(bad)-1] ^= 0xff
			return verifyToken(bad, opPut, shard, node, now)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.run(); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("%s: err = %v, want ErrUnauthorized", c.name, err)
			}
		})
	}
}

// --- server authorization harness -----------------------------------------

// newLedgerNode spins up a server host backed by `backing` and a temp-file
// ledger with the given options. Returns the host and the ledger.
func newLedgerNode(t *testing.T, backing store.Store, opts ledger.Options) (host.Host, *ledger.Ledger) {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), opts)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })
	srv := NewServer(backing, nil)
	srv.SetLedger(led)
	srv.Register(h)
	return h, led
}

// clientHost builds an ephemeral client host connected to server.
func clientHost(t *testing.T, server host.Host) host.Host {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Connect(ctx, h, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return h
}

// signedClient returns a NetStore signing with signer against server.
func signedClient(t *testing.T, server host.Host, signer cap.SignKey) *NetStore {
	return NewNetStoreSigned(clientHost(t, server), server.ID(), signer)
}

// TestOwnershipDelete is the headline scenario: two Users store the same bytes;
// one deleting drops only their claim, and the blob survives until the last
// owner deletes.
func TestOwnershipDelete(t *testing.T) {
	backing := store.NewMemStore()
	server, _ := newLedgerNode(t, backing, ledger.Options{})
	keyA, _, _ := cap.GenerateSigningKey()
	keyB, _, _ := cap.GenerateSigningKey()
	a := signedClient(t, server, keyA)
	b := signedClient(t, server, keyB)
	ctx := context.Background()

	data := []byte("bytes owned by both A and B")
	idA, err := a.Put(ctx, data)
	if err != nil {
		t.Fatalf("A put: %v", err)
	}
	idB, err := b.Put(ctx, data)
	if err != nil {
		t.Fatalf("B put: %v", err)
	}
	if idA != idB {
		t.Fatalf("same bytes gave different ids: %s != %s", idA, idB)
	}
	if ok, _ := backing.Has(ctx, idA); !ok {
		t.Fatal("blob absent after puts")
	}

	// B deletes: its claim drops, but A still owns the shard, so the blob stays.
	if err := b.Delete(ctx, idA); err != nil {
		t.Fatalf("B delete: %v", err)
	}
	if ok, _ := backing.Has(ctx, idA); !ok {
		t.Fatal("blob removed after B delete, but A still owns it")
	}
	got, err := a.Get(ctx, idA)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("A get after B delete: %v", err)
	}

	// A deletes: last owner gone, blob physically removed.
	if err := a.Delete(ctx, idA); err != nil {
		t.Fatalf("A delete: %v", err)
	}
	if ok, _ := backing.Has(ctx, idA); ok {
		t.Fatal("blob still present after last owner deleted")
	}
}

// TestCannotDeleteOthersShard proves a User cannot delete a shard they never
// stored.
func TestCannotDeleteOthersShard(t *testing.T) {
	backing := store.NewMemStore()
	server, _ := newLedgerNode(t, backing, ledger.Options{})
	keyA, _, _ := cap.GenerateSigningKey()
	keyB, _, _ := cap.GenerateSigningKey()
	a := signedClient(t, server, keyA)
	b := signedClient(t, server, keyB)
	ctx := context.Background()

	data := []byte("bob's private shard")
	idB, err := b.Put(ctx, data)
	if err != nil {
		t.Fatalf("B put: %v", err)
	}

	// A never owned it: the delete is refused and the bytes remain.
	if err := a.Delete(ctx, idB); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("A delete of B's shard = %v, want ErrUnauthorized", err)
	}
	if ok, _ := backing.Has(ctx, idB); !ok {
		t.Fatal("B's shard removed by unauthorized delete")
	}
	got, err := b.Get(ctx, idB)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("B get after A's failed delete: %v", err)
	}
}

// TestUnsignedWriteRejected checks that a client with no signing key cannot
// write to a ledger-backed node.
func TestUnsignedWriteRejected(t *testing.T) {
	server, _ := newLedgerNode(t, store.NewMemStore(), ledger.Options{})
	unsigned := NewNetStore(clientHost(t, server), server.ID())
	ctx := context.Background()

	if _, err := unsigned.Put(ctx, []byte("no token here")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unsigned put = %v, want ErrUnauthorized", err)
	}
}

// mintFailingKey returns a signing key whose public key does NOT satisfy puzzle
// at difficulty d — i.e. a plain, non-self-certifying identity. At small d a
// random key fails with overwhelming probability, so this returns quickly.
func mintFailingKey(t *testing.T, puzzle cap.Puzzle, d cap.Difficulty) cap.SignKey {
	t.Helper()
	for range 10000 {
		key, pub, err := cap.GenerateSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		if !cap.MeetsPoW(puzzle, pub[:], d) {
			return key
		}
	}
	t.Fatalf("could not find a key failing difficulty %d", d)
	return cap.SignKey{}
}

// TestPoWAdmission checks the node-side proof-of-work gate on PUT: a
// self-certifying owner is admitted; a plain owner below the difficulty is
// refused with ErrUnauthorized; and DELETE stays ungated.
func TestPoWAdmission(t *testing.T) {
	// SHA-256 keeps the test fast; difficulty 8 => ~256 attempts to mint.
	puzzle := cap.SHA256Puzzle{}
	const d cap.Difficulty = 8

	backing := store.NewMemStore()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })
	srv := NewServer(backing, nil)
	srv.SetLedger(led)
	srv.SetPoW(puzzle, d)
	srv.Register(h)
	ctx := context.Background()

	// A non-self-certifying owner is refused on PUT.
	weakKey := mintFailingKey(t, puzzle, d)
	weak := signedClient(t, h, weakKey)
	if _, err := weak.Put(ctx, []byte("from a cheap identity")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("weak-identity put = %v, want ErrUnauthorized", err)
	}

	// A self-certifying owner is admitted.
	strongKey, strongPub, err := cap.MintSigningKey(puzzle, d, nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !cap.MeetsPoW(puzzle, strongPub[:], d) { // sanity
		t.Fatal("minted key does not meet difficulty")
	}
	strong := signedClient(t, h, strongKey)
	id, err := strong.Put(ctx, []byte("from a self-certifying identity"))
	if err != nil {
		t.Fatalf("strong-identity put = %v, want success", err)
	}

	// DELETE is ungated: the same weak identity can still remove its own claims.
	// (It has none here, so this just confirms the gate does not reject the verb.)
	if err := weak.Delete(ctx, id); err != nil && !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("weak delete unexpected error: %v", err)
	}
}

// TestPoWDisabledByDefault confirms the gate is off unless configured: a plain
// keypair writes normally on a ledger node with no PoW policy.
func TestPoWDisabledByDefault(t *testing.T) {
	server, _ := newLedgerNode(t, store.NewMemStore(), ledger.Options{})
	key, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, key)
	if _, err := c.Put(context.Background(), []byte("no pow required")); err != nil {
		t.Fatalf("put with pow disabled = %v, want success", err)
	}
}

// TestQuotaEnforced checks a PUT past the owner's quota is rejected.
func TestQuotaEnforced(t *testing.T) {
	server, _ := newLedgerNode(t, store.NewMemStore(), ledger.Options{QuotaBytes: 10})
	key, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, key)
	ctx := context.Background()

	if _, err := c.Put(ctx, make([]byte, 10)); err != nil {
		t.Fatalf("put at quota: %v", err)
	}
	if _, err := c.Put(ctx, []byte("x")); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over-quota put = %v, want ErrQuotaExceeded", err)
	}
}
