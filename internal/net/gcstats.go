package net

import (
	"sync"
	"time"
)

// GCStats is a thread-safe collector for the node's garbage-collector activity,
// shared between the GC loop (which records each cycle) and the MetricsServer
// (which reads it for /status and /metrics). The zero value is not usable; build
// one with NewGCStats.
type GCStats struct {
	mu             sync.Mutex
	runs           int64
	totalReclaimed int64
	lastReclaimed  int
	lastDropped    int
	lastOrphans    int
	lastRun        time.Time
}

// NewGCStats returns an empty GCStats ready to record.
func NewGCStats() *GCStats { return &GCStats{} }

// Record notes one completed GC cycle: reclaimed is how many shards it freed,
// dropped how many ledger records it dropped as orphaned, and orphans how many
// on-disk blobs the reconcile pass found with no ledger record. now is the cycle
// time.
func (g *GCStats) Record(reclaimed, dropped, orphans int, now time.Time) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runs++
	g.totalReclaimed += int64(reclaimed)
	g.lastReclaimed = reclaimed
	g.lastDropped = dropped
	g.lastOrphans = orphans
	g.lastRun = now
}

// GCSnapshot is an immutable copy of GCStats for reporting.
type GCSnapshot struct {
	Runs            int64 `json:"runs"`
	ShardsReclaimed int64 `json:"shards_reclaimed_total"`
	LastReclaimed   int   `json:"last_reclaimed"`
	LastDropped     int   `json:"last_dropped_records"`
	LastOrphans     int   `json:"last_orphan_blobs"`
	LastRunUnix     int64 `json:"last_run_unix"` // 0 until the first cycle
}

// Snapshot returns the current counters. Safe on a nil receiver (returns zero).
func (g *GCStats) Snapshot() GCSnapshot {
	if g == nil {
		return GCSnapshot{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var lastRun int64
	if !g.lastRun.IsZero() {
		lastRun = g.lastRun.Unix()
	}
	return GCSnapshot{
		Runs:            g.runs,
		ShardsReclaimed: g.totalReclaimed,
		LastReclaimed:   g.lastReclaimed,
		LastDropped:     g.lastDropped,
		LastOrphans:     g.lastOrphans,
		LastRunUnix:     lastRun,
	}
}
