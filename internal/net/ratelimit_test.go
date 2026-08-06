package net

import (
	"testing"
	"time"
)

func TestOwnerRateLimiterDisabled(t *testing.T) {
	// rate <= 0 yields a nil limiter, and a nil *OwnerRateLimiter meters nothing.
	if l := NewOwnerRateLimiter(0, 10); l != nil {
		t.Fatalf("NewOwnerRateLimiter(0, _) = %v, want nil", l)
	}
	var l *OwnerRateLimiter
	if !l.Allow([]byte("owner"), time.Now()) {
		t.Fatal("nil limiter refused a write; a disabled limiter must allow everything")
	}
}

func TestOwnerRateLimiterEmptyOwnerUnmetered(t *testing.T) {
	// An empty owner (a grant-authorized maintenance write) has no identity to key a
	// bucket on, so it is never metered even with a strict limiter.
	l := NewOwnerRateLimiter(1, 1)
	now := time.Now()
	for i := range 100 {
		if !l.Allow(nil, now) {
			t.Fatalf("empty owner metered at write %d; maintenance writes must be exempt", i)
		}
	}
}

func TestOwnerRateLimiterBurstThenThrottle(t *testing.T) {
	l := NewOwnerRateLimiter(1, 3) // 3-token burst, 1 write/sec refill
	owner := []byte("owner-A")
	now := time.Now()

	// The burst allowance admits exactly 3 back-to-back writes.
	for i := range 3 {
		if !l.Allow(owner, now) {
			t.Fatalf("write %d refused within burst of 3", i)
		}
	}
	if l.Allow(owner, now) {
		t.Fatal("4th back-to-back write allowed; burst cap not enforced")
	}

	// After ~1s one token has refilled: one more write, then throttled again.
	now = now.Add(time.Second)
	if !l.Allow(owner, now) {
		t.Fatal("write refused after a 1s refill of a 1/s bucket")
	}
	if l.Allow(owner, now) {
		t.Fatal("second write in the same instant allowed; only one token refilled")
	}
}

func TestOwnerRateLimiterRefillCaps(t *testing.T) {
	l := NewOwnerRateLimiter(1, 2) // burst 2
	owner := []byte("owner-B")
	now := time.Now()

	// Spend the burst.
	l.Allow(owner, now)
	l.Allow(owner, now)
	// Idle a long time: refill must cap at burst (2), not accumulate unbounded.
	now = now.Add(time.Hour)
	if !l.Allow(owner, now) {
		t.Fatal("bucket did not refill after a long idle (1st token)")
	}
	if !l.Allow(owner, now) {
		t.Fatal("bucket did not refill to full burst after a long idle (2nd token)")
	}
	if l.Allow(owner, now) {
		t.Fatal("bucket refilled beyond burst; token accrual is not capped")
	}
}

func TestOwnerRateLimiterPerOwnerIsolation(t *testing.T) {
	l := NewOwnerRateLimiter(1, 1) // 1-token bucket per owner
	now := time.Now()
	a, b := []byte("owner-A"), []byte("owner-B")

	if !l.Allow(a, now) {
		t.Fatal("owner A's first write refused")
	}
	if l.Allow(a, now) {
		t.Fatal("owner A's second write allowed; bucket not exhausted")
	}
	// Owner B has its own independent bucket, unaffected by A exhausting theirs.
	if !l.Allow(b, now) {
		t.Fatal("owner B metered by owner A's spending; buckets must be per-owner")
	}
}

func TestOwnerRateLimiterPrunesIdleBuckets(t *testing.T) {
	l := NewOwnerRateLimiter(1, 1)
	now := time.Now()

	// Touch a bucket, then let it sit idle well past the prune window.
	l.Allow([]byte("gone-quiet"), now)
	if got := l.bucketCount(); got != 1 {
		t.Fatalf("bucket count after one owner = %d, want 1", got)
	}
	// A later Allow for a *different* owner triggers the periodic prune, which drops
	// the now-full, idle bucket of the first owner.
	now = now.Add(2 * rateBucketIdle)
	l.Allow([]byte("someone-else"), now)
	if got := l.bucketCount(); got != 1 {
		t.Fatalf("bucket count after prune = %d, want 1 (idle full bucket should be dropped)", got)
	}
}

// bucketCount reports the number of live per-owner buckets (test-only).
func (l *OwnerRateLimiter) bucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
