package net

import (
	"context"
	"crypto/rand"
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

	// abuse, when set, is fed a possession-lie strike whenever a target peer
	// accepts a shard but then fails to prove it holds it (a proven lie, not a
	// transport error) — the make-before-break check below. Left nil, no strike is
	// recorded (the move is still kept safely local).
	abuse *AbuseMonitor

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

// SetAbuseMonitor attaches the maintenance-abuse detector so a target peer that
// fails a possession proof after accepting a shard accrues a strike toward a
// local ban. Optional; call before RunOnce.
func (rb *Rebalancer) SetAbuseMonitor(a *AbuseMonitor) { rb.abuse = a }

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
		rb.log.Debug("rebalance: within threshold", "event", "rebalance.skip", "self", selfLoad.Frac(), "peer", targetLoad.Frac())
		return 0, nil
	}
	rb.log.Debug("rebalance: shedding to peer",
		"event", "rebalance.shed", "peer", target, "self", selfLoad.Frac(), "peer_frac", targetLoad.Frac(), "budget", budget)

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

		// Concentration cap (Architecture §3.4): never let one peer come to hold
		// more than m shards of a single stripe. With k+m shards and any k
		// reconstructing, a node holding >m shards that later drops them all makes
		// the stripe unrecoverable from that node alone — exactly the leverage a
		// shard-absorbing node seeks during diffusion. Count what the target
		// already holds of this stripe and skip the move if adding this shard would
		// breach the cap. Best-effort: a lying node can under-report Has to keep
		// attracting shards, but the proof-gated release below still bars any
		// durability loss.
		if row.M > 0 {
			held, err := rb.peerStripeLoad(ctx, ns, row.Siblings, row.ShardID, row.M)
			if err != nil {
				rb.log.Debug("rebalance: count peer stripe shards", "event", "rebalance.spread_check", "id", row.ShardID, "peer", target, "err", err)
				continue
			}
			if held >= row.M {
				rb.log.Debug("rebalance: skip to preserve stripe spread",
					"event", "rebalance.spread_cap", "id", row.ShardID, "peer", target, "held", held, "m", row.M)
				continue
			}
			rb.log.Debug("rebalance: stripe spread ok",
				"event", "rebalance.spread_ok", "id", row.ShardID, "peer", target, "held", held, "m", row.M)
		}

		// Make-before-break: place the shard on the peer (which records the stripe
		// and re-announces the CID) BEFORE dropping our copy. The peer's per-owner
		// quota check may reject it (ErrQuotaExceeded) — treat that as "peer is full
		// after all" and stop shedding to it this round.
		if _, err := ns.putGrant(ctx, data, desc, row.Grant, ReasonRebalance); err != nil {
			if errors.Is(err, ErrQuotaExceeded) {
				rb.log.Debug("rebalance: peer refused (quota)", "event", "rebalance.place_refused", "reason", "quota", "id", row.ShardID, "peer", target)
				break
			}
			rb.log.Debug("rebalance: place on peer", "event", "rebalance.place_failed", "id", row.ShardID, "peer", target, "err", err)
			continue
		}
		rb.log.Debug("rebalance: peer accepted shard",
			"event", "rebalance.placed", "id", row.ShardID, "peer", target, "bytes", len(data))

		// Proof-gated release: before dropping our only other copy, make the peer
		// prove it actually holds the exact bytes (fresh-nonce challenge-response,
		// the same Probe repair uses). A node that absorbs shards during diffusion
		// and then deletes them — or never truly stored them — fails this, so we
		// KEEP our copy and never surrender durability to a lying receiver
		// (Architecture §3.4). A proof mismatch (peer answered, wrong digest) is a
		// strong misbehaviour signal, so we stop shedding to it this round; a probe
		// transport error is inconclusive, so we merely keep this shard and move on.
		if ok, err := rb.confirmStored(ctx, ns, row.ShardID, data); err != nil {
			rb.log.Debug("rebalance: possession probe (keeping local copy)", "event", "rebalance.probe_error", "id", row.ShardID, "peer", target, "err", err)
			continue
		} else if !ok {
			rb.log.Warn("rebalance: peer failed possession proof; keeping local copy",
				"event", "rebalance.probe_fail", "id", row.ShardID, "peer", target)
			// A proven lie (peer answered, wrong digest): strike it toward a local
			// ban. A transport error above is inconclusive and never strikes.
			if rb.abuse != nil {
				rb.abuse.RecordPossessionLie(target, now)
			}
			break
		}
		rb.log.Debug("rebalance: peer proved possession",
			"event", "rebalance.probe_ok", "id", row.ShardID, "peer", target)

		// The peer now holds, advertises AND has proven possession of the shard;
		// release our local copy and accounting. If the release fails the shard is
		// merely stored twice — safe, and reclaimed later by GC/reconcile — so we
		// still count the move.
		if err := rb.release(ctx, row.ShardID); err != nil {
			rb.log.Warn("rebalance: release local copy", "event", "rebalance.release_failed", "id", row.ShardID, "err", err)
		}
		rb.markMoved(row.ShardID, now)
		budget -= int64(len(data))
		moved++
		rb.log.Info("rebalance: moved shard", "event", "rebalance.move", "id", row.ShardID, "to", target, "bytes", len(data))
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
			rb.log.Debug("rebalance: query load", "event", "rebalance.load_query_failed", "peer", p, "err", err)
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

// confirmStored challenges the peer (reached via ns) to prove it holds id's exact
// bytes, using a fresh CSPRNG nonce so a stale answer cannot be replayed. It
// returns (true, nil) only on a verified proof; want is our own copy of the bytes
// the proof is checked against.
func (rb *Rebalancer) confirmStored(ctx context.Context, ns *NetStore, id store.ShardID, want []byte) (bool, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return false, err
	}
	pctx, cancel := context.WithTimeout(ctx, balanceQueryTimeout)
	defer cancel()
	return ns.Probe(pctx, id, want, nonce)
}

// peerStripeLoad counts how many of a stripe's siblings the target (reached via
// ns) already holds, excluding the shard about to be moved. It stops as soon as
// it reaches limit siblings, since that is all the concentration check needs to
// know. A Has error is returned so the caller can skip the move rather than risk
// over-concentrating on an unverifiable peer.
func (rb *Rebalancer) peerStripeLoad(ctx context.Context, ns *NetStore, siblings []store.ShardID, exclude store.ShardID, limit int) (int, error) {
	held := 0
	for _, sib := range siblings {
		if sib == exclude {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, balanceQueryTimeout)
		ok, err := ns.Has(hctx, sib)
		cancel()
		if err != nil {
			return held, err
		}
		if ok {
			if held++; held >= limit {
				return held, nil
			}
		}
	}
	return held, nil
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
