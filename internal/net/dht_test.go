package net

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/pipeline"
	"revika/internal/store"
)

// newDHTNode spins up a server-role libp2p host with the shard/probe handlers,
// a DHT joined to the given bootstrap peers, and the DHT wired in as the shard
// server's announcer (so Put announces provider records). It returns the
// Discovery; the backing store the caller passed in remains theirs to inspect.
func newDHTNode(t *testing.T, mode DHTMode, backing store.Store, bootstrap ...string) *Discovery {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	t.Cleanup(func() { h.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	disc, err := NewDiscovery(ctx, h, DiscoveryConfig{Mode: mode, Bootstrap: bootstrap})
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	// Registered after the host so cleanup (LIFO) closes the DHT before the host.
	t.Cleanup(func() { disc.Close() })

	srv := NewServer(backing, nil)
	srv.SetAnnouncer(disc)
	srv.Register(h)
	return disc
}

// dhtAddr returns a dialable bootstrap multiaddr (with /p2p/<id>) for d's host.
func dhtAddr(d *Discovery) string {
	for _, a := range d.h.Addrs() {
		return a.String() + "/p2p/" + d.h.ID().String()
	}
	return ""
}

// waitRoutingTable blocks until d has at least one peer in its DHT routing table
// (populated asynchronously after a peer is identified as a DHT server).
func waitRoutingTable(t *testing.T, d *Discovery) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if d.RoutingTableSize() > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("DHT routing table stayed empty")
}

// waitProviders polls until at least one provider for id is discoverable via d.
func waitProviders(t *testing.T, d *Discovery, id store.ShardID) []peer.AddrInfo {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ps, err := d.FindProviders(ctx, id, 10)
		cancel()
		if err == nil && len(ps) > 0 {
			return ps
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("no providers appeared in time")
	return nil
}

// TestDHTProvideAndFind is the core Kademlia property: a node announces it holds
// a shard, and a different node — reachable only by bootstrapping into the DHT —
// discovers who has it, with no central server.
func TestDHTProvideAndFind(t *testing.T) {
	seedStore := store.NewMemStore()
	seed := newDHTNode(t, DHTModeServer, seedStore)
	finder := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))

	ctx := context.Background()
	data := []byte("find me over the dht")
	id, err := seedStore.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}

	waitRoutingTable(t, finder)
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := seed.Announce(actx, id); err != nil {
		t.Fatalf("announce: %v", err)
	}

	providers := waitProviders(t, finder, id)
	found := false
	for _, pi := range providers {
		if pi.ID == seed.h.ID() {
			found = true
		}
	}
	if !found {
		t.Fatalf("seed %s not among providers %v", seed.h.ID(), providers)
	}
}

// TestNodeAdvertiseAndFind checks storage-node service discovery: a node
// advertises itself and another node finds it via the DHT rendezvous namespace.
func TestNodeAdvertiseAndFind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	seed := newDHTNode(t, DHTModeServer, store.NewMemStore())
	seed.AdvertiseLoop(ctx)

	finder := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))
	waitRoutingTable(t, finder)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		fctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		nodes, err := finder.FindNodes(fctx, 10)
		c()
		if err == nil {
			for _, pi := range nodes {
				if pi.ID == seed.h.ID() {
					return // discovered
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("advertised storage node was not discovered")
}

type fakeAnnouncer struct{ ch chan store.ShardID }

func (f *fakeAnnouncer) Announce(_ context.Context, id store.ShardID) error {
	f.ch <- id
	return nil
}

// TestServerAnnouncesOnPut checks that a Server with an announcer advertises each
// shard it accepts.
func TestServerAnnouncesOnPut(t *testing.T) {
	fake := &fakeAnnouncer{ch: make(chan store.ShardID, 1)}

	serverHost, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { serverHost.Close() })
	srv := NewServer(store.NewMemStore(), nil)
	srv.SetAnnouncer(fake)
	srv.Register(serverHost)

	clientHost, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	t.Cleanup(func() { clientHost.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Connect(ctx, clientHost, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	data := []byte("announce me")
	id, err := NewNetStore(clientHost, serverHost.ID()).Put(ctx, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	select {
	case got := <-fake.ch:
		if got != id {
			t.Fatalf("announced %s, stored %s", got, id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not announce the shard on Put")
	}
}

// TestDHTStoreGet retrieves a shard purely by DHT discovery: the reader holds
// nothing locally and does not know the holder up front — it finds the provider
// via the DHT and fetches from it.
func TestDHTStoreGet(t *testing.T) {
	seedStore := store.NewMemStore()
	seed := newDHTNode(t, DHTModeServer, seedStore)
	reader := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))

	ctx := context.Background()
	data := []byte("retrieve me purely by discovery")
	id, err := seedStore.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	waitRoutingTable(t, reader)
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := seed.Announce(actx, id); err != nil {
		t.Fatalf("announce: %v", err)
	}
	waitProviders(t, reader, id)

	ds := NewDHTStore(reader.h, reader)
	got, err := ds.Get(ctx, id)
	if err != nil {
		t.Fatalf("DHTStore.Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("DHTStore returned wrong bytes")
	}
}

// TestPlacementEndToEnd is the payoff: a client stores a multi-chunk file across
// several DHT-discovered nodes (no single -node), the shards demonstrably spread
// across more than one node, and a *different* client reconstructs the file
// byte-exact using only DHT provider discovery.
func TestPlacementEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A three-node revika DHT: B and C bootstrap off A.
	sa := store.NewMemStore()
	a := newDHTNode(t, DHTModeServer, sa)
	sb := store.NewMemStore()
	b := newDHTNode(t, DHTModeServer, sb, dhtAddr(a))
	sc := store.NewMemStore()
	c := newDHTNode(t, DHTModeServer, sc, dhtAddr(a))
	for _, d := range []*Discovery{a, b, c} {
		d.AdvertiseLoop(ctx)
	}
	waitRoutingTable(t, b)
	waitRoutingTable(t, c)

	// Writer client: discover the storage nodes and connect to them.
	writer := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(a))
	waitRoutingTable(t, writer)
	nodeIDs := discoverAtLeast(t, writer, 3)

	ps, err := NewPlacementStore(writer.h, writer, nodeIDs)
	if err != nil {
		t.Fatalf("placement store: %v", err)
	}

	// A file spanning several chunks → many shards to spread (k=4,m=2 ⇒ 6/chunk).
	cfg := pipeline.Config{ChunkSize: 32 << 10, Params: pipeline.DefaultConfig().Params}
	orig := make([]byte, cfg.ChunkSize*2+321)
	for i := range orig {
		orig[i] = byte(i*31 + 7)
	}
	manifest, err := pipeline.StoreFile(ctx, ps, cfg, bytes.NewReader(orig))
	if err != nil {
		t.Fatalf("StoreFile via placement: %v", err)
	}

	// The shards must actually be spread across more than one node.
	counts := []int{listLen(t, sa), listLen(t, sb), listLen(t, sc)}
	nonEmpty := 0
	for _, n := range counts {
		if n > 0 {
			nonEmpty++
		}
	}
	if nonEmpty < 2 {
		t.Fatalf("shards did not spread across nodes: per-node counts = %v", counts)
	}

	// Reader client: reconstruct using only DHT discovery (no node addresses).
	reader := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(a))
	waitRoutingTable(t, reader)
	ds := NewDHTStore(reader.h, reader)

	// Announce is asynchronous; retry LoadFile until provider records propagate.
	var buf bytes.Buffer
	deadline := time.Now().Add(30 * time.Second)
	for {
		buf.Reset()
		err = pipeline.LoadFile(ctx, ds, manifest, &buf)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("LoadFile via DHT discovery: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !bytes.Equal(buf.Bytes(), orig) {
		t.Fatal("file reconstructed via DHT does not match original")
	}
}

// discoverAtLeast polls FindNodes until at least want storage nodes are found
// and connectable, returning their peer IDs.
func discoverAtLeast(t *testing.T, d *Discovery, want int) []peer.ID {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		infos, err := d.FindNodes(fctx, 10)
		if err == nil {
			var ids []peer.ID
			for _, pi := range infos {
				cctx, c := context.WithTimeout(context.Background(), connectTimeout)
				connErr := d.h.Connect(cctx, pi)
				c()
				if connErr == nil {
					ids = append(ids, pi.ID)
				}
			}
			cancel()
			if len(ids) >= want {
				return ids
			}
		} else {
			cancel()
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("discovered fewer than %d storage nodes", want)
	return nil
}

func listLen(t *testing.T, s *store.MemStore) int {
	t.Helper()
	ids, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(ids)
}
