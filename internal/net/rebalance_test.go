package net

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
	"revika/internal/stripe"
)

// balanceNode builds a ledger-backed server host that both stores shards and
// reports load, so it can be the *target* of a rebalance move (it must accept a
// grant PUT and answer the balance protocol). Returns the host, its backing
// store, and its ledger for assertions.
func balanceNode(t *testing.T, src LoadSource) (host.Host, store.Store, *ledger.Ledger) {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	backing := store.NewMemStore()
	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })
	srv := NewServer(backing, nil)
	srv.SetLedger(led)
	srv.SetLoadSource(src)
	srv.Register(h)
	return h, backing, led
}

// seedShard stores data into a node's own store and ledger with a stripe row, as
// though the node had accepted it earlier — the precondition for the Rebalancer
// to move it. Returns the shard ID and the granting owner's pubkey.
func seedShard(t *testing.T, backing store.Store, led *ledger.Ledger, data []byte) (store.ShardID, []byte) {
	t.Helper()
	ctx := context.Background()
	signer, ownerPub, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	id := store.HashOf(data)
	desc := descFor(id)
	grant, err := stripe.BuildGrant(signer, desc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backing.Put(ctx, data); err != nil {
		t.Fatal(err)
	}
	if _, err := led.AddOwner(id, ownerPub[:], int64(len(data)), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := led.PutStripe(id, desc.K, desc.M, desc.Shards, grant); err != nil {
		t.Fatal(err)
	}
	return id, ownerPub[:]
}

// TestRebalanceMovesShard is the end-to-end diffusion move: a full node offloads
// a shard to an emptier peer make-before-break — the peer ends up holding and
// owning the shard, and the source releases its local copy and accounting.
func TestRebalanceMovesShard(t *testing.T) {
	ctx := context.Background()

	// Target: nearly empty, so it attracts the shard.
	target, targetBacking, targetLed := balanceNode(t, func() (LoadReport, error) {
		return LoadReport{UsedBytes: 0, CapacityBytes: 1_000_000}, nil
	})

	// Self: a full node, connected to the target, holding one cold shard.
	selfBacking := store.NewMemStore()
	selfLed, err := ledger.Open(filepath.Join(t.TempDir(), "self-ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("self ledger: %v", err)
	}
	t.Cleanup(func() { selfLed.Close() })
	selfHost := clientHost(t, target) // ephemeral host connected to target

	data := []byte("cold shard to relocate")
	id, ownerPub := seedShard(t, selfBacking, selfLed, data)

	selfLoad := func() (LoadReport, error) {
		return LoadReport{UsedBytes: 1000, CapacityBytes: 1000}, nil // frac 1.0
	}
	peers := func(context.Context) ([]peer.ID, error) { return []peer.ID{target.ID()}, nil }

	rb := NewRebalancer(selfHost, selfBacking, selfLed, selfLoad, peers, nil)
	moved, err := rb.RunOnce(ctx, time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if moved != 1 {
		t.Fatalf("moved = %d, want 1", moved)
	}

	// Make-before-break: the target now holds the shard...
	if ok, _ := targetBacking.Has(ctx, id); !ok {
		t.Fatal("target does not hold the moved shard")
	}
	// ...and owns it, with the stripe context, under the granting User.
	used, n, _ := targetLed.Account(ownerPub)
	if n != 1 || used != int64(len(data)) {
		t.Fatalf("target owner account = %d bytes / %d shards, want %d/1", used, n, len(data))
	}
	if rows, _ := targetLed.Stripes(); len(rows) != 1 {
		t.Fatalf("target stripe rows = %d, want 1", len(rows))
	}

	// The source released its copy and accounting.
	if ok, _ := selfBacking.Has(ctx, id); ok {
		t.Fatal("source still holds the shard after move")
	}
	if rows, _ := selfLed.Stripes(); len(rows) != 0 {
		t.Fatalf("source stripe rows = %d, want 0", len(rows))
	}
}

// blackholeStore accepts writes and returns the correct content address but keeps
// nothing — a stand-in for a node that absorbs shards during diffusion and then
// (or immediately) drops them. Has/Get behave as if the bytes were never stored,
// so a possession probe against it always fails.
type blackholeStore struct{}

func (blackholeStore) Put(_ context.Context, data []byte) (store.ShardID, error) {
	return store.HashOf(data), nil
}
func (blackholeStore) Get(context.Context, store.ShardID) ([]byte, error) {
	return nil, store.ErrNotFound
}
func (blackholeStore) Has(context.Context, store.ShardID) (bool, error) { return false, nil }
func (blackholeStore) Delete(context.Context, store.ShardID) error      { return store.ErrNotFound }

// blackholeNode is a balanceNode whose blob backend silently discards everything,
// so it accepts a grant PUT but can never answer a possession probe.
func blackholeNode(t *testing.T, src LoadSource) host.Host {
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
	srv := NewServer(blackholeStore{}, nil)
	srv.SetLedger(led)
	srv.SetLoadSource(src)
	srv.Register(h)
	return h
}

// TestRebalanceProbeGatedRelease is the anti-grief guarantee: when the receiving
// peer cannot prove it holds the exact bytes after the make-before-break PUT, the
// source must NOT release its copy. A malicious node that reports itself empty to
// attract shards and then drops them gains nothing — durability is never
// surrendered to a peer that fails the possession proof.
func TestRebalanceProbeGatedRelease(t *testing.T) {
	ctx := context.Background()

	// Malicious target: nearly empty (attracts the shard), accepts the PUT, stores
	// nothing.
	target := blackholeNode(t, func() (LoadReport, error) {
		return LoadReport{UsedBytes: 0, CapacityBytes: 1_000_000}, nil
	})

	selfBacking := store.NewMemStore()
	selfLed, err := ledger.Open(filepath.Join(t.TempDir(), "self-ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("self ledger: %v", err)
	}
	t.Cleanup(func() { selfLed.Close() })
	selfHost := clientHost(t, target)

	data := []byte("a shard a liar will absorb and drop")
	id, _ := seedShard(t, selfBacking, selfLed, data)

	selfLoad := func() (LoadReport, error) {
		return LoadReport{UsedBytes: 1000, CapacityBytes: 1000}, nil // frac 1.0
	}
	peers := func(context.Context) ([]peer.ID, error) { return []peer.ID{target.ID()}, nil }

	rb := NewRebalancer(selfHost, selfBacking, selfLed, selfLoad, peers, nil)
	moved, err := rb.RunOnce(ctx, time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if moved != 0 {
		t.Fatalf("moved = %d, want 0 (peer failed possession proof)", moved)
	}
	// The source must KEEP its only durable copy and its accounting.
	if ok, _ := selfBacking.Has(ctx, id); !ok {
		t.Fatal("source released its copy to a peer that cannot prove possession")
	}
	if rows, _ := selfLed.Stripes(); len(rows) != 1 {
		t.Fatalf("source stripe rows = %d, want 1 (kept)", len(rows))
	}
}

// TestRebalanceStripeConcentrationCap confirms the diffusion path never moves a
// shard onto a peer that already holds m shards of the same stripe: doing so
// would let a single node's loss take out the whole stripe. Here k=1,m=1 and the
// peer already holds the sibling, so the shard must stay put.
func TestRebalanceStripeConcentrationCap(t *testing.T) {
	ctx := context.Background()

	target, targetBacking, _ := balanceNode(t, func() (LoadReport, error) {
		return LoadReport{UsedBytes: 0, CapacityBytes: 1_000_000}, nil
	})

	selfBacking := store.NewMemStore()
	selfLed, err := ledger.Open(filepath.Join(t.TempDir(), "self-ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("self ledger: %v", err)
	}
	t.Cleanup(func() { selfLed.Close() })
	selfHost := clientHost(t, target)

	data := []byte("cold shard whose stripe is already on the peer")
	id, _ := seedShard(t, selfBacking, selfLed, data)

	// The target already holds this stripe's other sibling (descFor uses M=1), so
	// it is already at the cap: moving id there would give one node 2 of a k=1,m=1
	// stripe — a single-node loss it could not survive.
	if _, err := targetBacking.Put(ctx, []byte("sibling-shard")); err != nil {
		t.Fatalf("seed sibling on target: %v", err)
	}

	selfLoad := func() (LoadReport, error) {
		return LoadReport{UsedBytes: 1000, CapacityBytes: 1000}, nil // frac 1.0
	}
	peers := func(context.Context) ([]peer.ID, error) { return []peer.ID{target.ID()}, nil }

	rb := NewRebalancer(selfHost, selfBacking, selfLed, selfLoad, peers, nil)
	moved, err := rb.RunOnce(ctx, time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if moved != 0 {
		t.Fatalf("moved = %d, want 0 (stripe concentration cap)", moved)
	}
	if ok, _ := selfBacking.Has(ctx, id); !ok {
		t.Fatal("source moved a shard that would over-concentrate the stripe")
	}
	if ok, _ := targetBacking.Has(ctx, id); ok {
		t.Fatal("target received a shard that breaches the stripe concentration cap")
	}
}

// TestRebalanceWithinThreshold confirms the dead-band: when the load gap is
// within the threshold, no shard is moved (this is what stops thrashing).
func TestRebalanceWithinThreshold(t *testing.T) {
	ctx := context.Background()

	target, targetBacking, _ := balanceNode(t, func() (LoadReport, error) {
		return LoadReport{UsedBytes: 450, CapacityBytes: 1000}, nil // frac 0.45
	})

	selfBacking := store.NewMemStore()
	selfLed, err := ledger.Open(filepath.Join(t.TempDir(), "self-ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("self ledger: %v", err)
	}
	t.Cleanup(func() { selfLed.Close() })
	selfHost := clientHost(t, target)

	data := []byte("a shard that should stay put")
	id, _ := seedShard(t, selfBacking, selfLed, data)

	selfLoad := func() (LoadReport, error) {
		return LoadReport{UsedBytes: 500, CapacityBytes: 1000}, nil // frac 0.50, gap 0.05 < 0.10
	}
	peers := func(context.Context) ([]peer.ID, error) { return []peer.ID{target.ID()}, nil }

	rb := NewRebalancer(selfHost, selfBacking, selfLed, selfLoad, peers, nil)
	moved, err := rb.RunOnce(ctx, time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if moved != 0 {
		t.Fatalf("moved = %d, want 0 (within threshold)", moved)
	}
	if ok, _ := selfBacking.Has(ctx, id); !ok {
		t.Fatal("source dropped a shard it should have kept")
	}
	if ok, _ := targetBacking.Has(ctx, id); ok {
		t.Fatal("target received a shard despite the dead-band")
	}
}
