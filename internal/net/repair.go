package net

import (
	"context"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/store"
	"revika/internal/stripe"
)

// RepairStore is the store.Store a repairing Node drives the repair engine
// (internal/repair) through. Reads resolve first against the repairing node's own
// blob store and then over the DHT (like a DHTStore) — so repair.Check probes
// shard survival and repair.Repair fetches the survivors it needs to reconstruct —
// while writes place each regenerated shard on a fresh Node, authorized not by an
// owner token (the repairing node holds no User key) but by the stripe's repair
// grant.
//
// Consulting the local store first is essential: the DHT's FindProviders excludes
// the querying host, so a node cannot discover its *own* shards over the DHT. A
// repairer that only asked the DHT would count every shard it holds locally as
// missing and wrongly declare an otherwise-recoverable stripe lost. The local
// store closes that blind spot.
//
// It is scoped to a single stripe: it carries that stripe's Descriptor and grant,
// so a regenerated shard is always accompanied by the exact metadata the
// receiving Node needs to verify the grant and, in turn, join the stripe's repair
// itself.
//
// Defence controls (security/Defence.md; primitives P6, P20 in security/frameworks.md):
//   SC-36 (Distributed Processing and Storage) — regenerated shards are placed on fresh nodes.
//   AC-3  (Access Enforcement)                  — each regenerated write is authorized by the stripe's signed grant.
type RepairStore struct {
	*DHTStore
	local store.Store // the repairing node's own blobs; consulted before the DHT
	disc  *Discovery
	desc  stripe.Descriptor
	grant []byte

	mu   sync.Mutex
	next int
}

// NewRepairStore returns a RepairStore for stripe d, reading first from local (the
// repairing node's own blob store, may be nil) then the DHT, placing regenerated
// shards via disc-discovered nodes and authorizing them with grant.
func NewRepairStore(h host.Host, local store.Store, disc *Discovery, d stripe.Descriptor, grant []byte) *RepairStore {
	return &RepairStore{DHTStore: NewDHTStore(h, disc), local: local, disc: disc, desc: d, grant: grant}
}

var _ store.Store = (*RepairStore)(nil)

// Delete is not meaningful for repair.
func (r *RepairStore) Delete(context.Context, store.ShardID) error { return ErrReadOnly }

// Has reports whether the shard survives anywhere the repairer can reach it: its
// own local store first (the DHT hides the querier's own provider records), then
// remote providers over the DHT.
func (r *RepairStore) Has(ctx context.Context, id store.ShardID) (bool, error) {
	if r.local != nil {
		if ok, err := r.local.Has(ctx, id); err == nil && ok {
			return true, nil
		}
	}
	return r.DHTStore.Has(ctx, id)
}

// Get fetches the shard from the local store if held there, else over the DHT.
func (r *RepairStore) Get(ctx context.Context, id store.ShardID) ([]byte, error) {
	if r.local != nil {
		if data, err := r.local.Get(ctx, id); err == nil {
			return data, nil
		}
	}
	return r.DHTStore.Get(ctx, id)
}

// Put places a regenerated shard on a storage node that does not already hold it,
// authorized by the stripe's repair grant. It skips nodes that are already
// providers (the shard is content-addressed and idempotent, but re-storing where
// it already lives buys no extra redundancy). If every discovered node already
// holds the shard, Put is a no-op success — coverage is already maximal.
func (r *RepairStore) Put(ctx context.Context, data []byte) (store.ShardID, error) {
	id := store.HashOf(data)

	holders := make(map[peer.ID]bool)
	if providers, err := r.disc.FindProviders(ctx, id, defaultMaxProviders); err == nil {
		for _, pi := range providers {
			holders[pi.ID] = true
		}
	}

	candidates, err := r.disc.FindNodes(ctx, defaultMaxProviders)
	if err != nil {
		return store.ShardID{}, fmt.Errorf("revika/net: repair find nodes: %w", err)
	}
	fresh := candidates[:0]
	for _, pi := range candidates {
		if !holders[pi.ID] {
			fresh = append(fresh, pi)
		}
	}
	if len(fresh) == 0 {
		// No fresh target: the shard is already as widely placed as the known
		// node set allows. Treat as success so repair does not report a failure.
		return id, nil
	}

	// Round-robin the starting point so a repair cycle regenerating several shards
	// spreads them over distinct nodes, then try each fresh candidate in turn: a
	// discovered node may be a stale advert for a peer that has since gone away, so
	// a single pick could fail even though other fresh nodes would accept it.
	r.mu.Lock()
	start := r.next
	r.next++
	r.mu.Unlock()

	var lastErr error
	for i := range fresh {
		pi := fresh[(start+i)%len(fresh)]
		if err := r.ensureConnected(ctx, pi); err != nil {
			lastErr = err
			continue
		}
		got, err := NewNetStore(r.h, pi.ID).putGrant(ctx, data, r.desc, r.grant)
		if err != nil {
			lastErr = err
			continue
		}
		return got, nil
	}
	return store.ShardID{}, fmt.Errorf("revika/net: repair place %s: no fresh node accepted it: %w", id, lastErr)
}
