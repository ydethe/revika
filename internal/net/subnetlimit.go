package net

import (
	"net"
	"sync"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// Axis A — identity-agnostic per-subnet flow cap (Architecture §3.1/§5; the outer
// DoS backstop that complements the per-owner limiters). A revika node is dumb
// about *content* but may defend its own availability: this limiter throttles how
// fast a single source *subnet* may drive shard/probe requests against this node,
// acting only on the connection's source IP — never on identity, never decrypting
// or interpreting a shard, so the untrusted-blob-store trust model is untouched.
//
// Why by subnet, not by owner: the per-owner quota and OwnerRateLimiter are only
// as strong as the identity is scarce, and identities are cheap to mint. This cap
// is deliberately blind to identity — it bounds a flood from one network location
// regardless of how many owner keys the attacker grinds. To exceed it an attacker
// must command many distinct IPs (a genuinely scarce, costly resource), not many
// free keypairs. It is the first line of defence and the one that does not depend
// on identity scarcity at all.
//
// It meters *every* shard verb (PUT/GET/HAS/DELETE) and every probe — including
// the read verbs the per-owner limiter never sees — since it runs before the frame
// is parsed and before any identity is known. That breadth is the point: it is a
// per-request control-plane check (a token-bucket lookup, sub-microsecond), never
// a per-byte data-plane cost, so it is invisible next to the shard scatter/gather
// that dominates R/W latency. Set the cap generously (well above legitimate
// inter-node repair/rebalance volume): unlike the owner limiter it cannot exempt
// maintenance traffic, because it acts before the frame that would identify it.
//
// It is a per-subnet token bucket: each source subnet gets a bucket of Burst
// tokens refilling at Rate tokens/second; a request costs one token, and an
// over-cap request is torn down (stream Reset) rather than answered — the cheapest
// rejection under flood. The limiter is entirely optional; a nil *SubnetRateLimiter
// meters nothing (the default). Addresses with no attributable IP (relay/unknown
// transport) fail open — there is no subnet to key a bucket on.
//
// Defence controls (security/Defence.md; primitive P9/P11 in security/frameworks.md):
//   SC-5 (Denial-of-Service Protection) — a per-subnet token bucket bounds the
//        request rate from any one network location, so a flood cannot be scaled
//        by minting fresh identities.
//   SC-7 (Boundary Protection)          — perimeter flow limit keyed on source IP.

// subnetBucketIdle is how long a full, untouched bucket is kept before prune drops
// it — mirrors rateBucketIdle. A bucket at full capacity is indistinguishable from
// a freshly created one, so dropping an idle full bucket is lossless.
const subnetBucketIdle = 10 * time.Minute

// Default aggregation prefixes: a /24 groups an IPv4 source network into one
// bucket, a /56 an IPv6 source (a typical residential IPv6 delegation), so an
// attacker cannot dodge the cap by walking host addresses within one allocation.
const (
	defaultSubnetPrefix4 = 24
	defaultSubnetPrefix6 = 56
)

// subnetBucket is one subnet's token bucket, refilled lazily on access.
type subnetBucket struct {
	tokens float64   // tokens currently available (0..burst)
	last   time.Time // when tokens was last brought up to date
}

// SubnetRateLimiter is a per-subnet token-bucket rate limiter for shard/probe
// requests. It is safe for concurrent use — the shard server drives it from many
// stream handlers. The zero value is not usable; build one with
// NewSubnetRateLimiter.
type SubnetRateLimiter struct {
	rate  float64  // tokens added per second, per subnet
	burst float64  // bucket capacity (max tokens, also the initial fill)
	mask4 net.IPMask // IPv4 aggregation mask
	mask6 net.IPMask // IPv6 aggregation mask

	mu        sync.Mutex
	buckets   map[string]*subnetBucket
	lastPrune time.Time
}

// NewSubnetRateLimiter builds a limiter admitting up to burst requests back-to-back
// per source subnet and refilling at rate requests per second. rate must be > 0; a
// burst below 1 is clamped to 1. prefix4/prefix6 are the IPv4/IPv6 aggregation
// prefix lengths; a value outside (0,32]/(0,128] falls back to the package default
// (/24, /56). Returns nil if rate <= 0, so a caller can pass a disabled
// configuration straight through (a nil *SubnetRateLimiter meters nothing — see
// Allow).
func NewSubnetRateLimiter(rate, burst float64, prefix4, prefix6 int) *SubnetRateLimiter {
	if rate <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	if prefix4 <= 0 || prefix4 > 32 {
		prefix4 = defaultSubnetPrefix4
	}
	if prefix6 <= 0 || prefix6 > 128 {
		prefix6 = defaultSubnetPrefix6
	}
	return &SubnetRateLimiter{
		rate:    rate,
		burst:   burst,
		mask4:   net.CIDRMask(prefix4, 32),
		mask6:   net.CIDRMask(prefix6, 128),
		buckets: map[string]*subnetBucket{},
	}
}

// Allow reports whether a request from addr is permitted at now, consuming one
// token when it is. A nil limiter always allows (the feature is off), so callers
// need not branch on whether the cap is configured. An address with no
// attributable IP (relay/unknown transport, or a nil addr) is allowed too — there
// is no subnet to key a bucket on, so this fails open rather than blocking traffic
// it cannot classify.
func (l *SubnetRateLimiter) Allow(addr ma.Multiaddr, now time.Time) bool {
	if l == nil {
		return true
	}
	key, ok := l.key(addr)
	if !ok {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	b := l.buckets[key]
	if b == nil {
		// A new subnet starts with a full bucket, then immediately spends one token.
		l.buckets[key] = &subnetBucket{tokens: l.burst - 1, last: now}
		return true
	}
	// Lazy refill: credit tokens accrued since last access, capped at burst, then
	// charge this request.
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

// key returns the masked-subnet bucket key for addr's IP, and whether an IP could
// be extracted. IPv4 (and v4-mapped) addresses are masked to mask4, others to
// mask6, so all hosts within one source subnet share a bucket.
func (l *SubnetRateLimiter) key(addr ma.Multiaddr) (string, bool) {
	if addr == nil {
		return "", false
	}
	ip, err := manet.ToIP(addr)
	if err != nil || ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return string(v4.Mask(l.mask4)), true
	}
	if v6 := ip.To16(); v6 != nil {
		return string(v6.Mask(l.mask6)), true
	}
	return "", false
}

// pruneLocked drops buckets that have refilled to full and been idle past
// subnetBucketIdle, bounding map growth over a long-running node's lifetime. A full
// bucket carries no state a fresh one would not reproduce, so this is lossless. It
// runs at most once per subnetBucketIdle window. Caller holds l.mu.
func (l *SubnetRateLimiter) pruneLocked(now time.Time) {
	if now.Sub(l.lastPrune) < subnetBucketIdle {
		return
	}
	l.lastPrune = now
	for key, b := range l.buckets {
		if now.Sub(b.last) < subnetBucketIdle {
			continue
		}
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, key)
		}
	}
}
