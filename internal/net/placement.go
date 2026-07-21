package net

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/store"
)

// defaultMaxProviders bounds how many providers we ask the DHT for per shard.
const defaultMaxProviders = 20

// ErrReadOnly is returned for write operations on a discovery-only store: it can
// find and fetch shards via the DHT, but deciding *where* a new shard goes is a
// placement decision (see PlacementStore), not a lookup.
var ErrReadOnly = errors.New("revika/net: store is read-only (retrieval via DHT); use a PlacementStore to write")

// DHTStore is a read-oriented store.Store whose backend is "whoever the DHT says
// holds this shard". On Get/Has it looks up the shard's provider records,
// connects to a provider, and fetches through a per-peer NetStore — so the
// pipeline's LoadFile runs unchanged, knowing nothing about where shards live.
type DHTStore struct {
	h    host.Host
	disc *Discovery
	max  int
}

// NewDHTStore returns a DHTStore over disc, dialing providers through h.
func NewDHTStore(h host.Host, disc *Discovery) *DHTStore {
	return &DHTStore{h: h, disc: disc, max: defaultMaxProviders}
}

var _ store.Store = (*DHTStore)(nil)

func (s *DHTStore) Put(context.Context, []byte) (store.ShardID, error) {
	return store.ShardID{}, ErrReadOnly
}

func (s *DHTStore) Delete(context.Context, store.ShardID) error { return ErrReadOnly }

func (s *DHTStore) Get(ctx context.Context, id store.ShardID) ([]byte, error) {
	providers, err := s.disc.FindProviders(ctx, id, s.max)
	if err != nil {
		return nil, err
	}
	if len(providers) == 0 {
		return nil, store.ErrNotFound
	}
	// Try providers in turn; the DHT can list stale ones, so a miss on one is
	// not fatal while another may still hold the (self-verifying) shard.
	lastErr := error(store.ErrNotFound)
	for _, pi := range providers {
		if err := s.ensureConnected(ctx, pi); err != nil {
			lastErr = err
			continue
		}
		data, err := NewNetStore(s.h, pi.ID).Get(ctx, id)
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	// Every known provider failed — the shard is a miss, a dead node holding a
	// stale provider record, or an unreachable one. From the store's point of
	// view the shard is simply unavailable, so map it to ErrNotFound: callers
	// like the pipeline's erasure decode then treat it as one lost shard and
	// rebuild from the survivors (any k of k+m) instead of aborting the whole
	// read. The concrete cause is wrapped in for diagnostics.
	return nil, fmt.Errorf("revika/net: shard %s unavailable from %d provider(s) (%v): %w", id, len(providers), lastErr, store.ErrNotFound)
}

func (s *DHTStore) Has(ctx context.Context, id store.ShardID) (bool, error) {
	providers, err := s.disc.FindProviders(ctx, id, s.max)
	if err != nil {
		return false, err
	}
	for _, pi := range providers {
		if err := s.ensureConnected(ctx, pi); err != nil {
			continue
		}
		if ok, err := NewNetStore(s.h, pi.ID).Has(ctx, id); err == nil && ok {
			return true, nil
		}
	}
	return false, nil
}

// ensureConnected dials pi if not already connected.
func (s *DHTStore) ensureConnected(ctx context.Context, pi peer.AddrInfo) error {
	if s.h.Network().Connectedness(pi.ID) == network.Connected {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := s.h.Connect(cctx, pi); err != nil {
		return fmt.Errorf("revika/net: connect provider %s: %w", pi.ID, err)
	}
	return nil
}

// PlacementStore is the write-side store.Store a User stores a file through. It
// spreads shards across a set of candidate nodes so no single node holds enough
// of any file to matter — the point of erasure coding "over the internet".
//
// Placement policy (first cut): round-robin across the candidate nodes. Because
// a chunk's k+m shards are Put consecutively by the pipeline, they land on
// consecutive distinct nodes whenever at least k+m candidates exist, giving the
// failure-domain diversity the erasure margin depends on. Each receiving node
// announces its own provider record on Put (Server.SetAnnouncer), so the shard
// becomes discoverable immediately.
//
// Reads (Get/Has) are resolved via the DHT exactly like DHTStore: placement
// decides where a shard goes, provider records record where it landed.
type PlacementStore struct {
	*DHTStore
	nodes  []peer.ID
	signer cap.SignKey

	mu   sync.Mutex
	next int
}

var _ store.Store = (*PlacementStore)(nil)

// NewPlacementStore returns a store that places shards across the given
// candidate nodes (h should already be connected to them). disc backs the read
// side, and signer authorizes the PUT/DELETE it issues to each node. It errors
// if the candidate set is empty.
func NewPlacementStore(h host.Host, disc *Discovery, nodes []peer.ID, signer cap.SignKey) (*PlacementStore, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("revika/net: no storage nodes available to place shards on")
	}
	return &PlacementStore{DHTStore: NewDHTStore(h, disc), nodes: nodes, signer: signer}, nil
}

// Nodes returns the candidate node set (for diagnostics/logging).
func (p *PlacementStore) Nodes() []peer.ID { return p.nodes }

// Put sends data to the next node in round-robin order and returns its content
// address. The chosen node stores the shard and announces its provider record.
func (p *PlacementStore) Put(ctx context.Context, data []byte) (store.ShardID, error) {
	p.mu.Lock()
	target := p.nodes[p.next%len(p.nodes)]
	p.next++
	p.mu.Unlock()
	return NewNetStoreSigned(p.h, target, p.signer).Put(ctx, data)
}

// Delete removes the caller's ownership claim on the shard from every node the
// DHT says holds it (best-effort). Each node drops only this owner's claim and
// frees the blob only when its own last owner leaves, so a signed Delete never
// affects another User's copy.
func (p *PlacementStore) Delete(ctx context.Context, id store.ShardID) error {
	providers, err := p.disc.FindProviders(ctx, id, p.max)
	if err != nil {
		return err
	}
	if len(providers) == 0 {
		return store.ErrNotFound
	}
	var deleted bool
	var lastErr error
	for _, pi := range providers {
		if err := p.ensureConnected(ctx, pi); err != nil {
			lastErr = err
			continue
		}
		if err := NewNetStoreSigned(p.h, pi.ID, p.signer).Delete(ctx, id); err != nil {
			lastErr = err
			continue
		}
		deleted = true
	}
	if !deleted {
		if lastErr != nil {
			return lastErr
		}
		return store.ErrNotFound
	}
	return nil
}
