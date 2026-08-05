package sync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"revika/internal/provider"
)

// TestE2EBidirectionalLifecycle drives two independent local mirrors (A and B)
// of one stored namespace through a full lifecycle — seed, propagate, edit both
// ways, delete both ways, and rename — asserting the two mirrors converge after
// each round. This is the package's headline path: everything flows through the
// real manifest Provider (encrypt → erasure-code → content-addressed store), so
// it exercises the whole client-side stack, not a stub.
func TestE2EBidirectionalLifecycle(t *testing.T) {
	ctx := context.Background()
	prov := newProvider(t)

	a, b := t.TempDir(), t.TempDir()
	ra, err := New(a, prov, WithConflictPolicy(PreferLocal))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := New(b, prov)
	if err != nil {
		t.Fatal(err)
	}

	// Round 1: A seeds a nested tree with a symlink and an empty directory.
	writeFile(t, a, "readme.md", "hello revika")
	writeFile(t, a, "docs/intro.txt", "intro")
	writeFile(t, a, "docs/deep/note.txt", "deep note")
	mkdirLocalHelper(t, a, "cache")
	symlink(t, a, "latest", "docs/intro.txt")

	mustReconcile(t, ra) // push A → remote
	mustReconcile(t, rb) // pull remote → B

	want := map[string]string{
		"readme.md":          "hello revika",
		"docs":               "D",
		"docs/intro.txt":     "intro",
		"docs/deep":          "D",
		"docs/deep/note.txt": "deep note",
		"cache":              "D",
		"latest":             "L:docs/intro.txt",
	}
	eqTree(t, treeOf(t, b), want)

	// Round 2: B edits a file and adds one; A edits a different file. No path
	// collides, so both sets of changes must merge cleanly.
	writeFile(t, b, "docs/intro.txt", "intro v2 (edited on B)")
	writeFile(t, b, "docs/new.txt", "added on B")
	writeFile(t, a, "readme.md", "hello revika, edited on A")

	mustReconcile(t, rb) // B's changes → remote
	mustReconcile(t, ra) // remote → A, and A's edit → remote
	mustReconcile(t, rb) // A's edit → B

	final := map[string]string{
		"readme.md":          "hello revika, edited on A",
		"docs":               "D",
		"docs/intro.txt":     "intro v2 (edited on B)",
		"docs/new.txt":       "added on B",
		"docs/deep":          "D",
		"docs/deep/note.txt": "deep note",
		"cache":              "D",
		"latest":             "L:docs/intro.txt",
	}
	eqTree(t, treeOf(t, a), final)
	eqTree(t, treeOf(t, b), final)

	// Round 3: a rename on A (surfaces as delete + add), and a delete on B.
	if err := os.Rename(filepath.Join(a, "readme.md"), filepath.Join(a, "README")); err != nil {
		t.Fatal(err)
	}
	// keep mtime distinct so the "added" side is detected as new content
	mt := nextMtime()
	os.Chtimes(filepath.Join(a, "README"), mt, mt)
	if err := os.Remove(filepath.Join(b, "docs/new.txt")); err != nil {
		t.Fatal(err)
	}

	mustReconcile(t, ra) // rename → remote (drop readme.md, add README)
	mustReconcile(t, rb) // B: pull rename, push its deletion
	mustReconcile(t, ra) // A: pull B's deletion

	renamed := map[string]string{
		"README":             "hello revika, edited on A",
		"docs":               "D",
		"docs/intro.txt":     "intro v2 (edited on B)",
		"docs/deep":          "D",
		"docs/deep/note.txt": "deep note",
		"cache":              "D",
		"latest":             "L:docs/intro.txt",
	}
	eqTree(t, treeOf(t, a), renamed)
	eqTree(t, treeOf(t, b), renamed)

	// A final pass on each side must be a no-op: the mirrors have converged.
	if pa, _ := ra.PlanOnly(ctx); !pa.Empty() {
		t.Fatalf("A not converged, pending: %+v", pa.Ops)
	}
	if pb, _ := rb.PlanOnly(ctx); !pb.Empty() {
		t.Fatalf("B not converged, pending: %+v", pb.Ops)
	}
}

// TestE2ELargeFileErasure round-trips a file bigger than one erasure chunk, so
// the sync path really drives multi-chunk StoreFile/LoadFile under the hood.
func TestE2ELargeFileErasure(t *testing.T) {
	prov := newProvider(t)
	a, b := t.TempDir(), t.TempDir()

	big := make([]byte, 300*1024)
	for i := range big {
		big[i] = byte(i*7 + 3)
	}
	if err := os.WriteFile(filepath.Join(a, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	mt := nextMtime()
	os.Chtimes(filepath.Join(a, "big.bin"), mt, mt)

	ra, _ := New(a, prov)
	rb, _ := New(b, prov)
	mustReconcile(t, ra)
	mustReconcile(t, rb)

	got, err := os.ReadFile(filepath.Join(b, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(big) {
		t.Fatalf("size mismatch: got %d, want %d", len(got), len(big))
	}
	for i := range big {
		if got[i] != big[i] {
			t.Fatalf("byte %d differs after erasure round-trip", i)
		}
	}
}

// TestE2EDaemonPolling runs the polling Daemon and asserts it reconciles new
// local files without an explicit Reconcile call — the "folder-watch" behavior.
func TestE2EDaemonPolling(t *testing.T) {
	prov := newProvider(t)
	a, b := t.TempDir(), t.TempDir()
	writeFile(t, a, "first.txt", "one")

	ra, _ := New(a, prov)
	results := make(chan Result, 16)
	daemon := NewDaemon(ra, 20*time.Millisecond, WithOnResult(func(r Result) {
		select {
		case results <- r:
		default:
		}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()

	// Wait until the first file has been uploaded (the immediate initial pass).
	waitForRemote(t, prov, "first.txt", 3*time.Second)

	// Drop a second file and let a later tick pick it up.
	writeFile(t, a, "second.txt", "two")
	waitForRemote(t, prov, "second.txt", 3*time.Second)

	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("daemon stopped with %v, want context.Canceled", err)
	}

	// Confirm a fresh mirror sees both files the daemon pushed.
	rb, _ := New(b, prov)
	mustReconcile(t, rb)
	eqTree(t, treeOf(t, b), map[string]string{
		"first.txt":  "one",
		"second.txt": "two",
	})
}

// waitForRemote polls the provider until a path appears in the stored tree or
// the timeout elapses.
func waitForRemote(t *testing.T, prov provider.Provider, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remote, err := scanRemote(context.Background(), prov)
		if err == nil {
			if _, ok := remote[path]; ok {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q to appear remotely", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
