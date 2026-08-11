package net

// authcache.go implements a bounded, time-windowed server-side token replay
// cache (issue #9). It records the signature of every valid write token the
// server accepts and rejects a second use of the same signature within its
// validity window (±tokenSkew from the timestamp). Because writes are
// owner-scoped and idempotent, replay within the window is harmless in
// practice, but eliminating it closes a theoretic race and hardens AU-10
// (non-repudiation) and SC-23 (session authenticity).
//
// Memory budget: at most one entry per token. Each entry is a 64-byte array
// key plus a time.Time value (~24 bytes) → ~88 bytes. A node taking 10 000
// token-writes per minute accumulates ≈880 kB over the 10-minute window —
// well within the expected footprint of a storage node.

import (
	"sync"
	"time"

	"revika/internal/cap"
)

// authCache is a mutex-protected map of token signatures to the time at which
// the cache entry expires. An entry expires when the token it covers can no
// longer be presented to the server (i.e. its timestamp is outside ±tokenSkew
// of the server clock), so it is safe to evict.
type authCache struct {
	mu      sync.Mutex
	entries map[[cap.SignatureSize]byte]time.Time
	lastGC  time.Time
}

// gcInterval is how often the cache scans for expired entries. One minute is
// a reasonable trade-off: a 5-minute window → at most 5 sweeps to empty it.
const authCacheGCInterval = time.Minute

func newAuthCache() *authCache {
	return &authCache{entries: make(map[[cap.SignatureSize]byte]time.Time)}
}

// seen records sig as seen at now and returns true if it was already in the
// cache (a replay). It evicts expired entries on a periodic schedule so memory
// stays bounded.
//
// The expiry stored is now + 2*tokenSkew. Rationale: verifyToken already
// accepted this token, so its timestamp ts satisfies |now-ts| ≤ tokenSkew,
// meaning the latest it can be validly presented is ts+tokenSkew ≤ now+2*tokenSkew.
// Keeping the entry until now+2*tokenSkew is therefore correct and conservative.
func (c *authCache) seen(sig [cap.SignatureSize]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if now.Sub(c.lastGC) >= authCacheGCInterval {
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
		c.lastGC = now
	}

	expiry := now.Add(2 * tokenSkew)
	if exp, ok := c.entries[sig]; ok && now.Before(exp) {
		return true // replay within the validity window
	}
	c.entries[sig] = expiry
	return false
}
