package net

import (
	"sync"
	"time"
)

// Write-verb rate limiting (Architecture §3.1/§5; the flow cap that complements
// the ledger's per-owner storage quota). A node is dumb about *content* but may
// defend its own availability: the limiter throttles how fast a single owner may
// drive write verbs (PUT/DELETE) against this node, acting only on the Ed25519
// owner identity recovered from the request's auth token — never decrypting or
// interpreting a shard, so the untrusted-blob-store trust model is untouched.
//
// It is a per-owner token bucket: each owner gets a bucket of Burst tokens that
// refills at Rate tokens per second. A write costs one token; when the bucket is
// empty the write is refused with statusRateLimited (ErrRateLimited) and the
// caller may retry after the bucket refills. This gates a write flood (an owner
// injecting new load faster than the node wants to absorb) while leaving the
// per-owner storage quota as the *volume* cap.
//
// Only *fresh, owner-initiated* writes are metered: the grant-authorized
// maintenance flows (repair regeneration, rebalance moves) carry no owner token
// and are exempt, exactly as proof-of-work admission exempts them — throttling
// mandatory repair would strand durability, and rebalance cadence is already
// policed by the AbuseMonitor. The limiter is entirely optional; a node with no
// limiter configured meters nothing (prior behaviour).
//
// Defence controls (security/Defence.md; primitive P9 in security/frameworks.md):
//   SC-5 (Denial-of-Service Protection) — a per-owner token bucket bounds write-verb
//        rate, so one identity cannot flood PUT/DELETE and starve the node.

// rateBucketIdle is how long a full, untouched bucket is kept before prune drops
// it. A bucket at full capacity is indistinguishable from a freshly created one
// (both start full), so dropping an idle full bucket is lossless — it just frees
// the map entry for an owner that has gone quiet.
const rateBucketIdle = 10 * time.Minute

// ownerBucket is one owner's token bucket, refilled lazily on access.
type ownerBucket struct {
	tokens float64   // tokens currently available (0..burst)
	last   time.Time // when tokens was last brought up to date
}

// OwnerRateLimiter is a per-owner token-bucket rate limiter for write verbs. It
// is safe for concurrent use — the shard server drives it from many stream
// handlers. The zero value is not usable; build one with NewOwnerRateLimiter.
type OwnerRateLimiter struct {
	rate  float64 // tokens added per second
	burst float64 // bucket capacity (max tokens, also the initial fill)

	mu        sync.Mutex
	buckets   map[string]*ownerBucket
	lastPrune time.Time
}

// NewOwnerRateLimiter builds a limiter admitting up to burst writes back-to-back
// per owner and refilling at rate writes per second. rate must be > 0; a burst
// below 1 is clamped to 1 (a bucket must hold at least one token or every write
// would be refused). Returns nil if rate <= 0, so a caller can pass a disabled
// configuration straight through (a nil *OwnerRateLimiter meters nothing — see
// Allow).
func NewOwnerRateLimiter(rate, burst float64) *OwnerRateLimiter {
	if rate <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &OwnerRateLimiter{
		rate:    rate,
		burst:   burst,
		buckets: map[string]*ownerBucket{},
	}
}

// Allow reports whether a write from owner is permitted at now, consuming one
// token when it is. A nil limiter always allows (the feature is off), so callers
// need not branch on whether rate limiting is configured. An empty owner is
// treated as unmetered too — there is no identity to key a bucket on (the
// grant-authorized maintenance flows carry no owner token).
func (l *OwnerRateLimiter) Allow(owner []byte, now time.Time) bool {
	if l == nil || len(owner) == 0 {
		return true
	}
	key := string(owner)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	b := l.buckets[key]
	if b == nil {
		// A new owner starts with a full bucket, then immediately spends one token.
		l.buckets[key] = &ownerBucket{tokens: l.burst - 1, last: now}
		return true
	}
	// Lazy refill: credit the tokens that have accrued since last access, capped at
	// burst, then charge this request.
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

// pruneLocked drops buckets that have refilled to full and been idle past
// rateBucketIdle, so the map cannot grow without bound over a long-running node's
// lifetime. A full bucket carries no state a fresh one would not reproduce, so
// this is lossless. It runs at most once per rateBucketIdle window. Caller holds
// l.mu.
func (l *OwnerRateLimiter) pruneLocked(now time.Time) {
	if now.Sub(l.lastPrune) < rateBucketIdle {
		return
	}
	l.lastPrune = now
	for key, b := range l.buckets {
		if now.Sub(b.last) < rateBucketIdle {
			continue
		}
		// Would this bucket have refilled to full by now? If so it is equivalent to
		// a fresh bucket and can be dropped.
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, key)
		}
	}
}
