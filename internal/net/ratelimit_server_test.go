package net

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
	"revika/internal/stripe"
)

// newRateLimitedNode spins up a ledger-backed server host that meters writes with
// limiter. Returns the host to dial and its backing store.
func newRateLimitedNode(t *testing.T, limiter *OwnerRateLimiter) (host.Host, store.Store) {
	t.Helper()
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
	backing := store.NewMemStore()
	srv := NewServer(backing, nil)
	srv.SetLedger(led)
	srv.SetRateLimiter(limiter)
	srv.Register(h)
	return h, backing
}

// TestWriteRateLimitPut is the core contract: a per-owner bucket admits a burst
// of owner PUTs, then refuses the next with ErrRateLimited (statusRateLimited).
func TestWriteRateLimitPut(t *testing.T) {
	ctx := context.Background()
	// burst 2, and a refill so slow no token returns during the test.
	server, backing := newRateLimitedNode(t, NewOwnerRateLimiter(0.001, 2))
	signer, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, signer)

	// The burst admits the first two distinct shards.
	if _, err := c.Put(ctx, []byte("shard-one")); err != nil {
		t.Fatalf("1st PUT within burst refused: %v", err)
	}
	if _, err := c.Put(ctx, []byte("shard-two")); err != nil {
		t.Fatalf("2nd PUT within burst refused: %v", err)
	}
	// The third owner PUT outpaces the bucket and is refused.
	_, err := c.Put(ctx, []byte("shard-three"))
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("3rd PUT error = %v, want ErrRateLimited", err)
	}
	// The refused shard must not have been stored.
	if ok, _ := backing.Has(ctx, store.HashOf([]byte("shard-three"))); ok {
		t.Fatal("rate-limited shard was stored anyway")
	}
}

// TestWriteRateLimitDelete confirms DELETE draws on the same per-owner bucket, so
// a delete flood is throttled too.
func TestWriteRateLimitDelete(t *testing.T) {
	ctx := context.Background()
	server, _ := newRateLimitedNode(t, NewOwnerRateLimiter(0.001, 1))
	signer, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, signer)

	// Two DELETEs for *distinct* shards so each produces a different signed token
	// (the token payload includes the shard ID, so identical shard IDs would
	// produce the same signature and the replay cache would intercept the second
	// request before the rate limiter sees it). The rate-limiter is per-owner, not
	// per-shard, so using different IDs still exercises the bucket.
	//
	// The first delete spends the one burst token (ledger then rejects the claim
	// because the owner never stored either shard). The second is refused by the
	// rate limiter bucket before the ledger is consulted.
	id1 := store.HashOf([]byte("never-stored-one"))
	id2 := store.HashOf([]byte("never-stored-two"))
	_ = c.Delete(ctx, id1) // spends the one burst token; ledger rejects (not owner)
	err := c.Delete(ctx, id2)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("2nd DELETE error = %v, want ErrRateLimited", err)
	}
}

// TestWriteRateLimitExemptsMaintenance is the durability guard: grant-authorized
// repair/rebalance writes carry no owner token, so they are never metered — even
// after an owner has exhausted their bucket. Throttling mandatory maintenance
// would strand data.
func TestWriteRateLimitExemptsMaintenance(t *testing.T) {
	ctx := context.Background()
	server, backing := newRateLimitedNode(t, NewOwnerRateLimiter(0.001, 1))
	signer, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, signer)

	// Exhaust the owner's single burst token with a normal write.
	if _, err := c.Put(ctx, []byte("owner-write")); err != nil {
		t.Fatalf("owner PUT refused: %v", err)
	}
	if _, err := c.Put(ctx, []byte("owner-write-2")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("owner over cap error = %v, want ErrRateLimited", err)
	}

	// A grant-authorized maintenance PUT (no owner token) for the SAME owner must
	// still be accepted — the limiter never sees an identity to key on.
	data := []byte("a repaired shard")
	id := store.HashOf(data)
	desc := descFor(id)
	grant, err := stripe.BuildGrant(signer, desc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.putGrant(ctx, data, desc, grant, ReasonRepair); err != nil {
		t.Fatalf("grant-authorized maintenance write was rate-limited: %v", err)
	}
	if ok, _ := backing.Has(ctx, id); !ok {
		t.Fatal("maintenance shard not stored")
	}
}
