package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"revika/internal/ledger"
	"revika/internal/net"
	"revika/internal/store"
)

// discardLogger is a logger whose output is thrown away — tests exercise the
// functions' control flow, not their log lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMultiFlag(t *testing.T) {
	var m multiFlag
	if got := m.String(); got != "" {
		t.Errorf("empty multiFlag String() = %q, want empty", got)
	}
	if err := m.Set("/ip4/127.0.0.1/tcp/1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := m.Set("/ip4/127.0.0.1/tcp/2"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("len after two Set = %d, want 2", len(m))
	}
	if got, want := m.String(), "/ip4/127.0.0.1/tcp/1,/ip4/127.0.0.1/tcp/2"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestSleepJitter(t *testing.T) {
	// A live context with a tiny interval returns true (the timer fires).
	if !sleepJitter(t.Context(), time.Millisecond) {
		t.Error("sleepJitter(live ctx, 1ms) = false, want true")
	}

	// A non-positive interval short-circuits: true on a live ctx, false on a
	// cancelled one (no sleep in either case).
	if !sleepJitter(t.Context(), 0) {
		t.Error("sleepJitter(live ctx, 0) = false, want true")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepJitter(cancelled, 0) {
		t.Error("sleepJitter(cancelled ctx, 0) = true, want false")
	}

	// A cancelled context with a long interval loses the race to ctx.Done(),
	// so the sleep is abandoned and the function reports false promptly.
	if sleepJitter(cancelled, time.Hour) {
		t.Error("sleepJitter(cancelled ctx, 1h) = true, want false")
	}
}

// TestDefaultQuotaBytes pins the secure-by-default per-owner ceiling (issue #22):
// 90% of a nominal 100 GiB node, expressed in bytes. A non-zero default is what
// bounds a single owner out of the box and activates the Axis B ramp, so a change
// here is a deliberate policy change and should update the flag help + docs too.
func TestDefaultQuotaBytes(t *testing.T) {
	const nominal = int64(100) * (1 << 30) // 100 GiB
	if want := nominal * 90 / 100; defaultQuotaBytes != want {
		t.Errorf("defaultQuotaBytes = %d, want %d (90%% of 100 GiB)", int64(defaultQuotaBytes), want)
	}
	if defaultQuotaBytes <= 0 {
		t.Error("defaultQuotaBytes must be > 0 so a fresh node bounds a single owner")
	}
}

// openLedger opens a fresh file-backed ledger for a test and registers cleanup.
func openLedger(t *testing.T, opts ledger.Options) *ledger.Ledger {
	t.Helper()
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), opts)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// TestRunGCTwoCycleGrace drives runGC's grace window: an unowned shard survives
// the first sweep (its collectible baseline) and is reclaimed on the second.
func TestRunGCTwoCycleGrace(t *testing.T) {
	blobs := store.NewMemStore()
	data := []byte("shard-bytes-for-gc")
	id, err := blobs.Put(t.Context(), data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	led := openLedger(t, ledger.Options{})
	owner := []byte("owner-pubkey")
	now := time.Now()
	if _, err := led.AddOwner(id, owner, int64(len(data)), now); err != nil {
		t.Fatalf("AddOwner: %v", err)
	}
	// Drop the only owner so the shard becomes collectible.
	if _, err := led.RemoveOwner(id, owner); err != nil {
		t.Fatalf("RemoveOwner: %v", err)
	}

	log := discardLogger()
	stats := net.NewGCStats()

	// Cycle 1: prev is nil, so the shard is only *noted* as collectible; grace
	// forbids deleting it this round.
	curr := runGC(t.Context(), blobs, led, log, false, nil, stats)
	if !curr[id] {
		t.Fatal("cycle 1: shard not reported collectible")
	}
	if ok, _ := blobs.Has(t.Context(), id); !ok {
		t.Fatal("cycle 1: shard deleted during grace window")
	}

	// Cycle 2: prev now carries the shard, so it has been collectible for two
	// consecutive cycles and is reclaimed. (The returned map is the snapshot
	// taken at the *start* of the cycle, before deletion, so it still lists id —
	// that is the baseline for a hypothetical third cycle.)
	runGC(t.Context(), blobs, led, log, false, curr, stats)
	if ok, _ := blobs.Has(t.Context(), id); ok {
		t.Error("cycle 2: shard not reclaimed after grace")
	}
	if snap := stats.Snapshot(); snap.ShardsReclaimed < 1 {
		t.Errorf("stats did not record a reclaim: %+v", snap)
	}
}

// TestRunGCCancelledContext confirms a cancelled context aborts the cycle
// without deleting anything, still returning the collectible baseline.
func TestRunGCCancelledContext(t *testing.T) {
	blobs := store.NewMemStore()
	data := []byte("shard-bytes-cancel")
	id, err := blobs.Put(t.Context(), data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	led := openLedger(t, ledger.Options{})
	owner := []byte("owner-pubkey")
	now := time.Now()
	if _, err := led.AddOwner(id, owner, int64(len(data)), now); err != nil {
		t.Fatalf("AddOwner: %v", err)
	}
	if _, err := led.RemoveOwner(id, owner); err != nil {
		t.Fatalf("RemoveOwner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the cycle runs

	// prev already carries the shard, so absent cancellation it would be deleted;
	// the cancelled context must stop the delete loop first.
	prev := map[store.ShardID]bool{id: true}
	runGC(ctx, blobs, led, discardLogger(), false, prev, net.NewGCStats())
	if ok, _ := blobs.Has(context.Background(), id); !ok {
		t.Error("cancelled cycle deleted a shard")
	}
}

// nonListerStore is a store.Store that deliberately does not implement
// store.Lister, so reprovideLoop takes its "not enumerable" early-return path.
type nonListerStore struct{ store.Store }

// TestReprovideLoopSkipsNonEnumerable covers reprovideLoop's guard: a store that
// cannot list its shards makes the loop log and return without touching the DHT.
func TestReprovideLoopSkipsNonEnumerable(t *testing.T) {
	// A nil *net.Discovery is safe: the non-Lister guard returns before any use.
	reprovideLoop(t.Context(), nil, nonListerStore{store.NewMemStore()}, discardLogger())
}

// TestLoopsExitOnCancel confirms the maintenance loops return promptly when their
// context is already cancelled, before touching their (here nil) collaborators.
func TestLoopsExitOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	led := openLedger(t, ledger.Options{})
	blobs := store.NewMemStore()
	log := discardLogger()

	// Each of these selects on ctx.Done() first, so a cancelled context ends the
	// loop on the first iteration. nil host/discovery/rebalancer are never used.
	gcLoop(ctx, blobs, led, log, time.Hour, false, net.NewGCStats())
	repairLoop(ctx, nil, blobs, nil, led, log, time.Hour, false, false)
	rebalanceLoop(ctx, nil, log, time.Hour)
}

// TestRunRepairEmptyLedger exercises the fast path: with no stripes recorded,
// runRepair lists an empty set and returns without touching the (nil) host or
// discovery, which the loop body never reaches.
func TestRunRepairEmptyLedger(t *testing.T) {
	led := openLedger(t, ledger.Options{})
	// h, disc, and blobs are only dereferenced inside the per-stripe loop, which
	// never runs for an empty ledger — nil is safe here.
	runRepair(t.Context(), nil, store.NewMemStore(), nil, led, discardLogger(), time.Hour, false, false)
}
