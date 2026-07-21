package net

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
	"revika/internal/stripe"
)

// newDHTLedgerNode is newDHTNode plus a ledger, so the server enforces
// authorization (token or grant) exactly as a real Node does. It returns the
// Discovery, the ledger, and the backing store for inspection.
func newDHTLedgerNode(t *testing.T, backing store.Store, bootstrap ...string) (*Discovery, *ledger.Ledger) {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	t.Cleanup(func() { h.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	disc, err := NewDiscovery(ctx, h, DiscoveryConfig{Mode: DHTModeServer, Bootstrap: bootstrap})
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	t.Cleanup(func() { disc.Close() })

	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })

	srv := NewServer(backing, nil)
	srv.SetLedger(led)
	srv.SetAnnouncer(disc)
	srv.Register(h)
	return disc, led
}

// TestRepairStoreCountsLocalShards is the regression guard for the repair blind
// spot that broke the autonomous-repair e2e: the DHT's FindProviders excludes the
// querying host, so a node cannot discover its *own* shards over the DHT. A
// RepairStore must consult its local store first — otherwise a repairer counts
// every shard it holds locally as missing and wrongly declares an
// otherwise-recoverable stripe unrecoverable, so no repair ever fires.
func TestRepairStoreCountsLocalShards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A shard the repairing node holds locally (and never reachable via the DHT's
	// self-excluding provider lookup).
	local := store.NewMemStore()
	data := []byte("a shard this node holds locally")
	id, err := local.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}

	// A lone DHT node with no bootstrap peers: any DHT query would find nothing, so
	// only the local store can surface this shard.
	node := newDHTNode(t, DHTModeServer, store.NewMemStore())
	rs := NewRepairStore(node.h, local, node, descFor(id), nil)

	ok, err := rs.Has(ctx, id)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !ok {
		t.Fatal("RepairStore.Has reported a locally-held shard as missing (DHT blind spot not covered)")
	}

	got, err := rs.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("RepairStore.Get returned wrong bytes for a locally-held shard")
	}
}

// TestRepairStorePlacesOnFreshNode is the RepairStore contract over a real DHT:
// given a shard already held (and announced) by one node, a RepairStore places a
// regenerated copy on a *different* discovered node — authorized purely by the
// stripe's repair grant (no owner token, no User key on the repairer) — and that
// node records ownership under the granting User.
func TestRepairStorePlacesOnFreshNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	holderStore := store.NewMemStore()
	holder, _ := newDHTLedgerNode(t, holderStore)
	freshStore := store.NewMemStore()
	fresh, freshLed := newDHTLedgerNode(t, freshStore, dhtAddr(holder))
	for _, d := range []*Discovery{holder, fresh} {
		d.AdvertiseLoop(ctx)
	}
	waitRoutingTable(t, fresh)

	// A repairer client that joined the DHT (it holds no User signing key).
	repairer := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(holder))
	waitRoutingTable(t, repairer)
	discoverAtLeast(t, repairer, 2)

	// The stripe and its grant, as they would have been distributed at store time.
	signer, ownerPub, _ := cap.GenerateSigningKey()
	data := []byte("a shard to be re-placed by repair")
	id := store.HashOf(data)
	desc := descFor(id)
	grant, err := stripe.BuildGrant(signer, desc, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Seed the shard onto the holder (grant-authorized) and wait for its provider
	// record to propagate so the repairer can see who already holds it.
	if _, err := NewNetStore(repairer.h, holder.h.ID()).putGrant(ctx, data, desc, grant); err != nil {
		t.Fatalf("seed holder: %v", err)
	}
	waitProviders(t, repairer, id)

	// Repair: place a regenerated copy. It must avoid the holder and land on fresh.
	// The repairer holds nothing locally here, so it reads purely over the DHT.
	rs := NewRepairStore(repairer.h, nil, repairer, desc, grant)
	got, err := rs.Put(ctx, data)
	if err != nil {
		t.Fatalf("RepairStore.Put: %v", err)
	}
	if got != id {
		t.Fatalf("RepairStore.Put id = %s, want %s", got, id)
	}

	// The fresh node now holds the shard, recorded under the granting User.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if ok, _ := freshStore.Has(ctx, id); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh node never received the regenerated shard")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if used, n, _ := freshLed.Account(ownerPub[:]); n != 1 || used != int64(len(data)) {
		t.Fatalf("fresh node owner account = %d/%d, want %d/1", used, n, len(data))
	}
}
