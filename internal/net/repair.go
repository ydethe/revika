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
// (internal/repair) through. Reads resolve over the DHT exactly like a DHTStore
// — so repair.Check probes shard survival and repair.Repair fetches the
// survivors it needs to reconstruct — while writes place each regenerated shard
// on a fresh Node, authorized not by an owner token (the repairing node holds no
// User key) but by the stripe's repair grant.
//
// It is scoped to a single stripe: it carries that stripe's Descriptor and grant,
// so a regenerated shard is always accompanied by the exact metadata the
// receiving Node needs to verify the grant and, in turn, join the stripe's repair
// itself.
type RepairStore struct {
	*DHTStore
	disc  *Discovery
	desc  stripe.Descriptor
	grant []byte

	mu   sync.Mutex
	next int
}

// NewRepairStore returns a RepairStore for stripe d, placing regenerated shards
// via disc-discovered nodes and authorizing them with grant.
func NewRepairStore(h host.Host, disc *Discovery, d stripe.Descriptor, grant []byte) *RepairStore {
	return &RepairStore{DHTStore: NewDHTStore(h, disc), disc: disc, desc: d, grant: grant}
}

var _ store.Store = (*RepairStore)(nil)

// Delete is not meaningful for repair.
func (r *RepairStore) Delete(context.Context, store.ShardID) error { return ErrReadOnly }

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

	// Round-robin across the fresh candidates so a single repair cycle that
	// regenerates several shards spreads them over distinct nodes.
	r.mu.Lock()
	pi := fresh[r.next%len(fresh)]
	r.next++
	r.mu.Unlock()

	if err := r.ensureConnected(ctx, pi); err != nil {
		return store.ShardID{}, err
	}
	return NewNetStore(r.h, pi.ID).putGrant(ctx, data, r.desc, r.grant)
}
