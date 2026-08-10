package net

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
)

// newSubnetLimitedNode spins up a ledger-backed server host whose Axis A per-subnet
// flow cap is limiter. Returns the host to dial and its backing store.
func newSubnetLimitedNode(t *testing.T, limiter *SubnetRateLimiter) (host.Host, store.Store) {
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
	srv.SetSubnetRateLimiter(limiter)
	srv.Register(h)
	return h, backing
}

// TestSubnetRateLimitTearsDownOverCap is the Axis A server contract: a burst-1
// per-subnet cap admits one request from a source subnet, then tears down the next
// from the same subnet (a stream Reset the client sees as an error) — independent
// of owner identity. Both requests here come from the same signed owner, but the
// cap keys on the source IP subnet (loopback), not the owner, so it would fire the
// same way across many freshly minted identities from one location.
func TestSubnetRateLimitTearsDownOverCap(t *testing.T) {
	ctx := context.Background()
	// burst 1, and a refill so slow no token returns during the test.
	server, backing := newSubnetLimitedNode(t, NewSubnetRateLimiter(0.001, 1, 24, 56))
	signer, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, signer)

	// The single burst token admits the first request.
	if _, err := c.Put(ctx, []byte("first")); err != nil {
		t.Fatalf("1st request within burst refused: %v", err)
	}
	// The second request from the same subnet is over the cap and torn down, so the
	// client sees an error and the shard is never stored.
	if _, err := c.Put(ctx, []byte("second")); err == nil {
		t.Fatal("2nd request over subnet cap succeeded; expected teardown")
	}
	if ok, _ := backing.Has(ctx, store.HashOf([]byte("second"))); ok {
		t.Fatal("over-cap shard was stored anyway")
	}
}

// TestSubnetRateLimitDisabledAdmitsAll confirms a nil (disabled) Axis A limiter
// meters nothing: many back-to-back requests all succeed.
func TestSubnetRateLimitDisabledAdmitsAll(t *testing.T) {
	ctx := context.Background()
	server, _ := newSubnetLimitedNode(t, nil)
	signer, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, signer)

	for i, data := range [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")} {
		if _, err := c.Put(ctx, data); err != nil {
			t.Fatalf("request %d refused with subnet cap disabled: %v", i, err)
		}
	}
}
