package net

import (
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Maintenance-abuse detection (Architecture §3.4 / §5). A node is dumb about
// *content* but may defend its own availability: the abuse detector watches the
// two grant-authorized maintenance flows a peer drives against this node —
// rebalance moves and possession probes — and locally blacklists a peer that
// abuses them, without ever decrypting or interpreting a shard. It acts only on
// connection/identity metadata (which peer, how often), so the untrusted-blob-
// store trust model is untouched. The blacklist is local and persistent (see
// Blocklister); banning by identity is weak while identities are free to mint
// (global anti-Sybil is deferred — Architecture §5), but it raises the cost of a
// misbehaving peer and, with proof-of-work identities, is not free to evade.
//
// Two independent triggers:
//
//   - Off-schedule rebalancing (fast-side only). A well-behaved peer initiates a
//     rebalance sweep roughly once per cluster interval. This detector flags a peer
//     whose sweeps arrive TOO FAST — gap < interval − tolerance — and bans on the
//     first such violation. Too-slow is fine (a lightly loaded peer may never need
//     to shed). One rebalance sweep sends many shard PUTs back-to-back, so moves
//     within a coalesce window count as a single event; the first event only sets
//     the baseline. The tolerance absorbs network jitter — a strict comparison
//     would false-positive constantly.
//
//   - Possession lies (strike budget). A peer that claims to hold a shard but fails
//     a fresh-nonce possession proof (the make-before-break check in rebalance, and
//     repair's survival probe) is lying about durability. A single failure can be a
//     race, so this accrues decaying strikes and bans at a threshold.

// Abuse-detector defaults. Tolerance and Decay are absolute; Coalesce is derived
// from the rebalance interval (a sweep's PUT burst is far shorter than a quarter
// interval) but capped so a very long interval does not make the window absurd.
const (
	defaultAbuseTolerance    = 10 * time.Minute
	defaultAbuseCoalesceCap  = 5 * time.Minute
	defaultAbuseStrikes      = 3
	defaultAbuseDecay        = 24 * time.Hour
	defaultAbuseCoalesceFrac = 4 // coalesce window = interval / this, capped above
)

// peerBlocker is the subset of *Blocklister the monitor needs: ban a peer by
// identity. Kept an interface so tests can substitute a recorder.
type peerBlocker interface {
	Block(p peer.ID, reason string)
}

// AbuseConfig tunes the abuse detector. A zero field takes its default via
// withDefaults, so a caller need only override what it cares about. RebalanceInterval
// is the effective cluster rebalance schedule (the same value the local Rebalancer
// runs on) and is the yardstick the off-schedule check measures a peer against; a
// zero interval disables off-schedule policing (nothing to compare to).
type AbuseConfig struct {
	RebalanceInterval time.Duration // cluster rebalance period; 0 disables off-schedule policing
	Tolerance         time.Duration // fast-side slack absorbing jitter (default 10m)
	Coalesce          time.Duration // moves within this window are one sweep (default min(interval/4, 5m))
	Strikes           int           // possession lies before a ban (default 3)
	Decay             time.Duration // strike expiry window (default 24h)
}

// withDefaults returns a copy with zero fields filled in.
func (c AbuseConfig) withDefaults() AbuseConfig {
	if c.Tolerance == 0 {
		c.Tolerance = defaultAbuseTolerance
	}
	if c.Coalesce == 0 {
		c.Coalesce = defaultAbuseCoalesceCap
		if c.RebalanceInterval > 0 {
			if q := c.RebalanceInterval / defaultAbuseCoalesceFrac; q < c.Coalesce {
				c.Coalesce = q
			}
		}
	}
	if c.Strikes == 0 {
		c.Strikes = defaultAbuseStrikes
	}
	if c.Decay == 0 {
		c.Decay = defaultAbuseDecay
	}
	return c
}

// peerAbuse is per-peer abuse bookkeeping.
type peerAbuse struct {
	lastMove  time.Time   // last individual rebalance-move PUT (coalescing anchor)
	lastEvent time.Time   // start of the last coalesced rebalance sweep
	haveEvent bool        // a baseline sweep has been seen
	strikes   []time.Time // possession-lie timestamps within the decay window
}

// AbuseMonitor implements the maintenance-abuse triggers over a peerBlocker. It
// is safe for concurrent use (the shard server feeds it from many stream
// handlers, the rebalancer from its loop).
type AbuseMonitor struct {
	cfg AbuseConfig
	bl  peerBlocker
	log *slog.Logger

	mu    sync.Mutex
	peers map[peer.ID]*peerAbuse
}

// NewAbuseMonitor builds a monitor that bans via bl. cfg is normalized through
// withDefaults. If log is nil, logging is discarded.
func NewAbuseMonitor(bl peerBlocker, cfg AbuseConfig, log *slog.Logger) *AbuseMonitor {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &AbuseMonitor{
		cfg:   cfg.withDefaults(),
		bl:    bl,
		log:   log,
		peers: map[peer.ID]*peerAbuse{},
	}
}

// RecordRebalanceMove notes one grant-authorized rebalance-move PUT received from
// p at now, and bans p if its sweeps arrive faster than the cluster schedule
// allows. Moves within the coalesce window are folded into one sweep; the first
// sweep from a peer only establishes the baseline. Off-schedule policing is
// skipped entirely when the cluster runs no rebalance schedule (interval 0).
func (m *AbuseMonitor) RecordRebalanceMove(p peer.ID, now time.Time) {
	if m.cfg.RebalanceInterval <= 0 {
		return // no schedule to measure against
	}
	m.mu.Lock()
	st := m.peers[p]
	if st == nil {
		// First move ever from this peer: baseline the sweep, do not judge it.
		m.peers[p] = &peerAbuse{lastMove: now, lastEvent: now, haveEvent: true}
		m.mu.Unlock()
		return
	}
	if now.Sub(st.lastMove) < m.cfg.Coalesce {
		// Same sweep (back-to-back PUTs): extend the burst, no new-event judgement.
		st.lastMove = now
		m.mu.Unlock()
		return
	}
	// A new sweep begins. Measure the gap since the previous sweep started.
	gap := now.Sub(st.lastEvent)
	st.lastEvent = now
	st.lastMove = now
	// Fast-side only: too-fast is abuse, too-slow is fine.
	tooFast := st.haveEvent && gap < m.cfg.RebalanceInterval-m.cfg.Tolerance
	st.haveEvent = true
	m.mu.Unlock()

	if tooFast {
		m.log.Warn("abuse: peer rebalances off-schedule (too fast)",
			"event", "abuse.rebalance_fast", "peer", p,
			"gap", gap.Round(time.Second), "interval", m.cfg.RebalanceInterval, "tolerance", m.cfg.Tolerance)
		m.bl.Block(p, "rebalance off-schedule (too fast)")
	}
}

// RecordPossessionLie notes that p failed a possession proof for a shard it
// should hold (a proven lie, not a transport error) at now, and bans p once the
// number of such lies within the decay window reaches the strike budget.
func (m *AbuseMonitor) RecordPossessionLie(p peer.ID, now time.Time) {
	m.mu.Lock()
	st := m.peers[p]
	if st == nil {
		st = &peerAbuse{}
		m.peers[p] = st
	}
	// Prune expired strikes, then record this one.
	cutoff := now.Add(-m.cfg.Decay)
	kept := st.strikes[:0]
	for _, t := range st.strikes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.strikes = append(kept, now)
	n := len(st.strikes)
	over := n >= m.cfg.Strikes
	if over {
		st.strikes = nil // reset so a re-admitted identity starts fresh
	}
	m.mu.Unlock()

	if over {
		m.log.Warn("abuse: peer exceeded possession-lie strikes",
			"event", "abuse.possession_strikes", "peer", p, "strikes", n, "budget", m.cfg.Strikes)
		m.bl.Block(p, "repeated possession lies")
	} else {
		m.log.Debug("abuse: possession lie recorded",
			"event", "abuse.possession_lie", "peer", p, "strikes", n, "budget", m.cfg.Strikes)
	}
}
