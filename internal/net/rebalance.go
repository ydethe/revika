package net

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/ledger"
	"revika/internal/placement"
	"revika/internal/store"
	"revika/internal/stripe"
)

// coldShardScan bounds how many of a node's coldest shards a single rebalance
// round examines — enough to fill a round's move budget without loading the whole
// stripe table.
const coldShardScan = 256

// Rebalancer sheds shards from this node to emptier peers so that, asymptotically,
// every node in a connected network comes to rest at the same *fraction* of its
// capacity used — the pairwise diffusion (dimension-exchange) load balancer of
// Architecture §3.4. Each round it samples a few peers, picks the emptiest, and —
// only if this node is fuller than that peer by more than a threshold (the
// dead-band that stops thrashing) — moves its coldest shards there make-before-
// break: the shard is placed (and re-announced in the DHT) on the peer first, and
// only then dropped locally, so the network never loses the address of a shard
// mid-move. Erasure coding covers any transient gap.
//
// A per-shard cooldown prevents a just-moved shard from bouncing back next round.
// Moves are authorized by the stripe's stored repair grant (the same mechanism as
// repair), so the Rebalancer never needs a User's signing key.
type Rebalancer struct {
	h     host.Host
	blobs store.Store
	led   *ledger.Ledger
	self  LoadSource
	// peers yields the candidate storage nodes to consider shedding to (e.g. a
	// closure over Discovery.FindNodes). Made pluggable so it can be driven from a
	// fixed list in tests, without a live DHT.
	peers func(context.Context) ([]peer.ID, error)
	log   *slog.Logger

	threshold float64       // load-fraction dead-band before offloading (0..1)
	sample    int           // peers sampled per round (power-of-k-choices)
	cooldown  time.Duration // per-shard move lockout

	mu    sync.Mutex
	moved map[store.ShardID]time.Time // shard -> last moved-away time
}

// NewRebalancer builds a Rebalancer. self reports this node's load; peers yields
// candidate targets. Defaults: threshold 0.10, 3 peers sampled per round, a
// one-hour per-shard cooldown — tune with the setters. If log is nil, logging is
// discarded.
func NewRebalancer(h host.Host, blobs store.Store, led *ledger.Ledger, self LoadSource, peers func(context.Context) ([]peer.ID, error), log *slog.Logger) *Rebalancer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Rebalancer{
		h:         h,
		blobs:     blobs,
		led:       led,
		self:      self,
		peers:     peers,
		log:       log,
		threshold: 0.10,
		sample:    3,
		cooldown:  time.Hour,
		moved:     map[store.ShardID]time.Time{},
	}
}

// SetThreshold sets the minimum load-fraction gap (0..1) before offloading.
func (rb *Rebalancer) SetThreshold(t float64) { rb.threshold = t }

// SetSample sets how many peers are queried per round (power-of-k choices). A
// value < 1 is clamped to 1.
func (rb *Rebalancer) SetSample(n int) {
	if n < 1 {
		n = 1
	}
	rb.sample = n
}

// SetCooldown sets how long a moved shard is locked out from moving again.
func (rb *Rebalancer) SetCooldown(d time.Duration) { rb.cooldown = d }

// RunOnce performs one rebalance round and returns the number of shards moved.
// now is the reference time for cooldown bookkeeping (pass time.Now()). It is a
// no-op success when this node has no capacity signal, no peers are reachable, or
// no sampled peer is emptier than this node by more than the threshold.
func (rb *Rebalancer) RunOnce(ctx context.Context, now time.Time) (int, error) {
	selfRep, err := rb.self()
	if err != nil {
		return 0, fmt.Errorf("revika/net: rebalance self load: %w", err)
	}
	selfLoad := selfRep.Load()
	if selfLoad.Capacity <= 0 {
		// No trustworthy capacity signal: we cannot reason about fractions, so we
		// stay put rather than move blindly.
		return 0, nil
	}

	target, targetLoad, ok, err := rb.pickTarget(ctx, now)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}

	budget := placement.OffloadBytes(selfLoad, targetLoad, rb.threshold)
	if budget <= 0 {
		rb.log.Debug("rebalance: within threshold", "self", selfLoad.Frac(), "peer", targetLoad.Frac())
		return 0, nil
	}
	rb.log.Debug("rebalance: shedding to peer",
		"peer", target, "self", selfLoad.Frac(), "peer_frac", targetLoad.Frac(), "budget", budget)

	rb.pruneCooldown(now)

	rows, err := rb.led.ColdShards(coldShardScan)
	if err != nil {
		return 0, fmt.Errorf("revika/net: rebalance cold shards: %w", err)
	}

	ns := NewNetStore(rb.h, target)
	moved := 0
	for _, row := range rows {
		if ctx.Err() != nil {
			break
		}
		if budget <= 0 {
			break
		}
		if rb.inCooldown(row.ShardID, now) {
			continue
		}
		data, err := rb.blobs.Get(ctx, row.ShardID)
		if err != nil {
			// The shard vanished from under us (GC, delete); skip it.
			rb.log.Debug("rebalance: read local shard", "id", row.ShardID, "err", err)
			continue
		}
		desc := stripe.Descriptor{K: row.K, M: row.M, Shards: row.Siblings}

		// Make-before-break: place the shard on the peer (which records the stripe
		// and re-announces the CID) BEFORE dropping our copy. The peer's per-owner
		// quota check may reject it (ErrQuotaExceeded) — treat that as "peer is full
		// after all" and stop shedding to it this round.
		if _, err := ns.putGrant(ctx, data, desc, row.Grant); err != nil {
			if errors.Is(err, ErrQuotaExceeded) {
				rb.log.Debug("rebalance: peer refused (quota)", "id", row.ShardID, "peer", target)
				break
			}
			rb.log.Debug("rebalance: place on peer", "id", row.ShardID, "peer", target, "err", err)
			continue
		}

		// The peer now holds and advertises the shard; release our local copy and
		// accounting. If the release fails the shard is merely stored twice — safe,
		// and reclaimed later by GC/reconcile — so we still count the move.
		if err := rb.release(ctx, row.ShardID); err != nil {
			rb.log.Warn("rebalance: release local copy", "id", row.ShardID, "err", err)
		}
		rb.markMoved(row.ShardID, now)
		budget -= int64(len(data))
		moved++
		rb.log.Info("rebalance: moved shard", "id", row.ShardID, "to", target, "bytes", len(data))
	}
	return moved, nil
}

// pickTarget samples up to rb.sample candidate peers, queries each one's declared
// load, and returns the emptiest. ok is false when no peer is reachable/queryable.
// now is unused for selection but kept for symmetry with cooldown-aware callers.
func (rb *Rebalancer) pickTarget(ctx context.Context, now time.Time) (peer.ID, placement.Load, bool, error) {
	_ = now
	candidates, err := rb.peers(ctx)
	if err != nil {
		return "", placement.Load{}, false, fmt.Errorf("revika/net: rebalance peers: %w", err)
	}
	self := rb.h.ID()
	sampled := make([]peer.ID, 0, rb.sample)
	for _, p := range candidates {
		if p == self {
			continue // never shed to ourselves
		}
		sampled = append(sampled, p)
		if len(sampled) >= rb.sample {
			break
		}
	}
	if len(sampled) == 0 {
		return "", placement.Load{}, false, nil
	}

	var (
		best     peer.ID
		bestLoad placement.Load
		haveBest bool
	)
	for _, p := range sampled {
		if ctx.Err() != nil {
			return "", placement.Load{}, false, ctx.Err()
		}
		qctx, cancel := context.WithTimeout(ctx, balanceQueryTimeout)
		rep, err := QueryLoad(qctx, rb.h, p)
		cancel()
		if err != nil {
			rb.log.Debug("rebalance: query load", "peer", p, "err", err)
			continue
		}
		l := rep.Load()
		if !haveBest || l.Frac() < bestLoad.Frac() {
			best, bestLoad, haveBest = p, l, true
		}
	}
	return best, bestLoad, haveBest, nil
}

// release removes a shard's local blob and drops its ledger record, crediting the
// owners' quota back — the node no longer holds the shard after a move. A blob
// already gone is fine (idempotent).
func (rb *Rebalancer) release(ctx context.Context, id store.ShardID) error {
	if err := rb.blobs.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return rb.led.DropRecord(id)
}

func (rb *Rebalancer) inCooldown(id store.ShardID, now time.Time) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	t, ok := rb.moved[id]
	return ok && now.Sub(t) < rb.cooldown
}

func (rb *Rebalancer) markMoved(id store.ShardID, now time.Time) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.moved[id] = now
}

// pruneCooldown drops cooldown entries older than the cooldown window so the map
// cannot grow without bound over a long-running node's lifetime.
func (rb *Rebalancer) pruneCooldown(now time.Time) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for id, t := range rb.moved {
		if now.Sub(t) >= rb.cooldown {
			delete(rb.moved, id)
		}
	}
}
