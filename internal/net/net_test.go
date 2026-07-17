package net

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/pipeline"
	"revika/internal/repair"
	"revika/internal/store"
)

// newLinkedPair spins up a server node (backed by backing) and a client host,
// connects them, and returns a NetStore the client can use to reach the server.
// Both hosts use ephemeral identities and are closed via t.Cleanup.
func newLinkedPair(t *testing.T, backing store.Store) *NetStore {
	t.Helper()

	serverHost, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { serverHost.Close() })
	NewServer(backing, nil).Register(serverHost)

	clientHost, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	t.Cleanup(func() { clientHost.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info := peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}
	if err := Connect(ctx, clientHost, info); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return NewNetStore(clientHost, serverHost.ID())
}

// TestNetStoreRoundTrip exercises every verb of the shard protocol against a
// real (in-process) libp2p connection.
func TestNetStoreRoundTrip(t *testing.T) {
	backing := store.NewMemStore()
	ns := newLinkedPair(t, backing)
	ctx := context.Background()

	data := []byte("the quick brown fox jumps over the lazy dog")

	// Put returns the true content address.
	id, err := ns.Put(ctx, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if id != store.HashOf(data) {
		t.Fatalf("Put id = %s, want %s", id, store.HashOf(data))
	}

	// The server's own store actually holds it.
	if ok, _ := backing.Has(ctx, id); !ok {
		t.Fatal("server store does not hold the shard after Put")
	}

	// Has over the wire.
	ok, err := ns.Has(ctx, id)
	if err != nil || !ok {
		t.Fatalf("Has = %v, %v; want true, nil", ok, err)
	}

	// Get returns identical bytes.
	got, err := ns.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Get returned %q, want %q", got, data)
	}

	// Delete, then Has is false and Get is ErrNotFound.
	if err := ns.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := ns.Has(ctx, id); ok {
		t.Fatal("Has true after Delete")
	}
	if _, err := ns.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Delete: err = %v, want ErrNotFound", err)
	}
	if err := ns.Delete(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete absent: err = %v, want ErrNotFound", err)
	}
}

// TestNetStoreErrorMapping checks that store errors survive the round trip.
func TestNetStoreErrorMapping(t *testing.T) {
	ns := newLinkedPair(t, store.NewMemStore())
	ctx := context.Background()

	var absent store.ShardID // all-zero id, never stored
	if _, err := ns.Get(ctx, absent); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get absent: err = %v, want ErrNotFound", err)
	}
	if ok, err := ns.Has(ctx, absent); err != nil || ok {
		t.Fatalf("Has absent = %v, %v; want false, nil", ok, err)
	}
}

// TestProbe checks proof-of-possession: a node holding the shard proves it, and
// a probe for an absent shard reports not-found.
func TestProbe(t *testing.T) {
	backing := store.NewMemStore()
	ns := newLinkedPair(t, backing)
	ctx := context.Background()

	data := []byte("prove you have this")
	id, err := ns.Put(ctx, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ok, err := ns.Probe(ctx, id, data, nonce)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !ok {
		t.Fatal("Probe failed for a shard the node holds")
	}

	// A node that lacks the shard cannot answer.
	var absent store.ShardID
	if _, err := ns.Probe(ctx, absent, []byte("whatever"), nonce); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Probe absent: err = %v, want ErrNotFound", err)
	}

	// Wrong local copy => proof mismatch (node has different bytes than we
	// think it does), so verification returns false, not an error.
	ok, err = ns.Probe(ctx, id, []byte("wrong bytes"), nonce)
	if err != nil {
		t.Fatalf("Probe mismatch: unexpected err %v", err)
	}
	if ok {
		t.Fatal("Probe verified against wrong local bytes")
	}
}

// TestPipelineOverNetwork is the payoff: the encode/repair stack runs unchanged
// against a remote node, because NetStore is just another store.Store. It
// stores a multi-chunk file over the wire, degrades it by deleting shards, then
// repairs and reads it back byte-exact.
func TestPipelineOverNetwork(t *testing.T) {
	backing := store.NewMemStore()
	ns := newLinkedPair(t, backing)
	ctx := context.Background()

	// A few chunks worth of deterministic data.
	cfg := pipeline.Config{ChunkSize: 64 << 10, Params: pipeline.DefaultConfig().Params}
	orig := make([]byte, cfg.ChunkSize*2+1234)
	for i := range orig {
		orig[i] = byte(i * 7)
	}

	manifest, err := pipeline.StoreFile(ctx, ns, cfg, bytes.NewReader(orig))
	if err != nil {
		t.Fatalf("StoreFile over net: %v", err)
	}

	// Healthy read-back.
	var buf bytes.Buffer
	if err := pipeline.LoadFile(ctx, ns, manifest, &buf); err != nil {
		t.Fatalf("LoadFile over net: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), orig) {
		t.Fatal("round-trip over net did not preserve bytes")
	}

	// Degrade: drop one shard from every chunk (within the erasure margin),
	// then confirm repair detects and restores it — all over the wire.
	for _, ch := range manifest.Chunks {
		if err := ns.Delete(ctx, ch.Shards[0]); err != nil {
			t.Fatalf("degrade: %v", err)
		}
	}
	rep, err := repair.Check(ctx, ns, manifest)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Healthy() {
		t.Fatal("expected unhealthy report after dropping shards")
	}
	if _, err := repair.Repair(ctx, ns, manifest); err != nil {
		t.Fatalf("Repair over net: %v", err)
	}
	rep, err = repair.Check(ctx, ns, manifest)
	if err != nil {
		t.Fatalf("Check after repair: %v", err)
	}
	if !rep.Healthy() {
		t.Fatalf("still unhealthy after repair: %d shards missing", rep.MissingShards())
	}

	buf.Reset()
	if err := pipeline.LoadFile(ctx, ns, manifest, &buf); err != nil {
		t.Fatalf("LoadFile after repair: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), orig) {
		t.Fatal("post-repair read-back over net did not preserve bytes")
	}
}

// TestIdentityPersistence checks that a node keeps a stable PeerID across
// restarts by persisting its key.
func TestIdentityPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "node.key")

	h1, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, IdentityPath: path})
	if err != nil {
		t.Fatalf("host 1: %v", err)
	}
	id1 := h1.ID()
	h1.Close()

	h2, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, IdentityPath: path})
	if err != nil {
		t.Fatalf("host 2: %v", err)
	}
	defer h2.Close()
	if h2.ID() != id1 {
		t.Fatalf("PeerID changed across restart: %s != %s", h2.ID(), id1)
	}
}
