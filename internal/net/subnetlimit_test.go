package net

import (
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
)

// addr builds a TCP multiaddr for ip, for keying the subnet limiter in tests.
func addr(t *testing.T, ip string) ma.Multiaddr {
	t.Helper()
	a, err := ma.NewMultiaddr("/ip4/" + ip + "/tcp/4001")
	if err != nil {
		// try IPv6
		a, err = ma.NewMultiaddr("/ip6/" + ip + "/tcp/4001")
	}
	if err != nil {
		t.Fatalf("build multiaddr for %q: %v", ip, err)
	}
	return a
}

func TestSubnetRateLimiterDisabled(t *testing.T) {
	// rate <= 0 yields a nil limiter, and a nil *SubnetRateLimiter meters nothing.
	if l := NewSubnetRateLimiter(0, 10, 24, 56); l != nil {
		t.Fatalf("NewSubnetRateLimiter(0, ...) = %v, want nil", l)
	}
	var l *SubnetRateLimiter
	if !l.Allow(addr(t, "203.0.113.7"), time.Now()) {
		t.Fatal("nil limiter refused a request; a disabled limiter must allow everything")
	}
}

func TestSubnetRateLimiterUnattributableFailsOpen(t *testing.T) {
	// An address with no IP component (or a nil addr) cannot be keyed to a subnet,
	// so it is allowed rather than blocked — the limiter never throttles traffic it
	// cannot classify.
	l := NewSubnetRateLimiter(1, 1, 24, 56)
	now := time.Now()
	if !l.Allow(nil, now) {
		t.Fatal("nil addr metered; unattributable traffic must fail open")
	}
	relay, err := ma.NewMultiaddr("/dns4/example.com/tcp/4001")
	if err != nil {
		t.Fatalf("build dns multiaddr: %v", err)
	}
	for i := range 100 {
		if !l.Allow(relay, now) {
			t.Fatalf("dns (no-IP) addr metered at request %d; must fail open", i)
		}
	}
}

func TestSubnetRateLimiterBurstThenThrottle(t *testing.T) {
	l := NewSubnetRateLimiter(1, 3, 24, 56) // 3-token burst, 1 req/sec refill
	a := addr(t, "203.0.113.10")
	now := time.Now()

	for i := range 3 {
		if !l.Allow(a, now) {
			t.Fatalf("request %d refused within burst of 3", i)
		}
	}
	if l.Allow(a, now) {
		t.Fatal("4th back-to-back request allowed; burst cap not enforced")
	}
	// After ~1s one token refills.
	now = now.Add(time.Second)
	if !l.Allow(a, now) {
		t.Fatal("request refused after a 1s refill of a 1/s bucket")
	}
	if l.Allow(a, now) {
		t.Fatal("second request in the same instant allowed; only one token refilled")
	}
}

func TestSubnetRateLimiterSharesBucketWithinSubnet(t *testing.T) {
	// Two distinct hosts in the same /24 share one bucket: an attacker cannot dodge
	// the cap by walking host addresses within a subnet it controls.
	l := NewSubnetRateLimiter(1, 1, 24, 56)
	now := time.Now()
	if !l.Allow(addr(t, "203.0.113.1"), now) {
		t.Fatal("first host's request refused")
	}
	if l.Allow(addr(t, "203.0.113.2"), now) {
		t.Fatal("a sibling host in the same /24 got a fresh token; subnet aggregation not applied")
	}
}

func TestSubnetRateLimiterPerSubnetIsolation(t *testing.T) {
	// Different /24s have independent buckets.
	l := NewSubnetRateLimiter(1, 1, 24, 56)
	now := time.Now()
	if !l.Allow(addr(t, "203.0.113.9"), now) {
		t.Fatal("subnet A's first request refused")
	}
	if l.Allow(addr(t, "203.0.113.9"), now) {
		t.Fatal("subnet A's second request allowed; bucket not exhausted")
	}
	if !l.Allow(addr(t, "198.51.100.9"), now) {
		t.Fatal("subnet B metered by subnet A's spending; buckets must be per-subnet")
	}
}

func TestSubnetRateLimiterIPv6Prefix(t *testing.T) {
	// Two addresses in the same /56 share a bucket; a different /56 does not.
	l := NewSubnetRateLimiter(1, 1, 24, 56)
	now := time.Now()
	if !l.Allow(addr(t, "2001:db8:abcd:0100::1"), now) {
		t.Fatal("first IPv6 host's request refused")
	}
	if l.Allow(addr(t, "2001:db8:abcd:01ff::2"), now) {
		t.Fatal("sibling in the same /56 got a fresh token; IPv6 aggregation not applied")
	}
	if !l.Allow(addr(t, "2001:db8:abcd:0200::1"), now) {
		t.Fatal("a different /56 was metered by the first; IPv6 buckets must be per-/56")
	}
}

func TestSubnetRateLimiterPrunesIdleBuckets(t *testing.T) {
	l := NewSubnetRateLimiter(1, 1, 24, 56)
	now := time.Now()
	l.Allow(addr(t, "203.0.113.5"), now)
	if got := l.bucketCount(); got != 1 {
		t.Fatalf("bucket count after one subnet = %d, want 1", got)
	}
	// A later Allow for a different subnet triggers the periodic prune, dropping the
	// now-full, idle bucket of the first subnet.
	now = now.Add(2 * subnetBucketIdle)
	l.Allow(addr(t, "198.51.100.5"), now)
	if got := l.bucketCount(); got != 1 {
		t.Fatalf("bucket count after prune = %d, want 1 (idle full bucket should be dropped)", got)
	}
}

// bucketCount reports the number of live per-subnet buckets (test-only).
func (l *SubnetRateLimiter) bucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
