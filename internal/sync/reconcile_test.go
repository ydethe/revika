package sync

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/provider"
	"revika/internal/store"
)

// newProvider builds an in-memory manifest Provider over a fresh MemStore, the
// backing a reconciler syncs against in tests.
func newProvider(t *testing.T) provider.Provider {
	t.Helper()
	signer, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	p, err := provider.New(context.Background(), store.NewMemStore(), signer, provider.NewMemRootStore())
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	return p
}

// mtimeCounter yields strictly increasing timestamps so a rewrite always looks
// newer than the previous version, independent of the filesystem's timestamp
// resolution.
var mtimeCounter int64 = 1_700_000_000

func nextMtime() time.Time {
	mtimeCounter++
	return time.Unix(mtimeCounter, 0)
}

// writeFile writes content to <root>/<rel>, creating parent directories, and
// stamps a fresh mtime so change detection is deterministic.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := nextMtime()
	if err := os.Chtimes(abs, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func mkdirLocalHelper(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, root, rel, target string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, abs); err != nil {
		t.Fatal(err)
	}
}

// treeOf snapshots a directory into a comparable map: "D" for a directory,
// "L:<target>" for a symlink, and the file content otherwise. The state sidecar
// is excluded.
func treeOf(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if abs == root {
			return nil
		}
		rel, _ := relSlash(root, abs)
		if rel == StateFileName {
			return nil
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			out[rel] = "D"
		case fi.Mode()&fs.ModeSymlink != 0:
			tgt, _ := os.Readlink(abs)
			out[rel] = "L:" + tgt
		default:
			b, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			out[rel] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("treeOf: %v", err)
	}
	return out
}

func eqTree(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("tree size mismatch: got %d entries %v, want %d %v", len(got), got, len(want), want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("entry %q = %q, want %q\nfull got: %v", k, got[k], v, got)
		}
	}
}

func mustReconcile(t *testing.T, r *Reconciler) Result {
	t.Helper()
	res, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, e := range res.Errors {
		t.Fatalf("reconcile op error: %v", e)
	}
	return res
}

func TestUploadNewTree(t *testing.T) {
	prov := newProvider(t)
	local := t.TempDir()
	writeFile(t, local, "a.txt", "alpha")
	writeFile(t, local, "sub/b.txt", "bravo")
	mkdirLocalHelper(t, local, "empty")

	r, err := New(local, prov)
	if err != nil {
		t.Fatal(err)
	}
	res := mustReconcile(t, r)
	if res.Uploaded != 2 {
		t.Fatalf("uploaded = %d, want 2", res.Uploaded)
	}

	// Download into a fresh dir to confirm the remote tree matches.
	dst := t.TempDir()
	r2, err := New(dst, prov)
	if err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r2)
	eqTree(t, treeOf(t, dst), map[string]string{
		"a.txt":     "alpha",
		"sub":       "D",
		"sub/b.txt": "bravo",
		"empty":     "D",
	})
}

func TestModifyLocalPropagates(t *testing.T) {
	prov := newProvider(t)
	local := t.TempDir()
	writeFile(t, local, "f.txt", "one")
	r, _ := New(local, prov)
	mustReconcile(t, r)

	writeFile(t, local, "f.txt", "one-modified-longer")
	res := mustReconcile(t, r)
	if res.Uploaded != 1 {
		t.Fatalf("uploaded = %d, want 1", res.Uploaded)
	}

	dst := t.TempDir()
	r2, _ := New(dst, prov)
	mustReconcile(t, r2)
	if got := treeOf(t, dst)["f.txt"]; got != "one-modified-longer" {
		t.Fatalf("downloaded content = %q, want modified", got)
	}
}

func TestModifyRemotePropagatesToLocal(t *testing.T) {
	prov := newProvider(t)
	// Seed remote via mirror A.
	a := t.TempDir()
	writeFile(t, a, "f.txt", "v1")
	ra, _ := New(a, prov)
	mustReconcile(t, ra)

	// Mirror B downloads it.
	b := t.TempDir()
	rb, _ := New(b, prov)
	mustReconcile(t, rb)

	// A changes it and pushes; B must pull the change.
	writeFile(t, a, "f.txt", "v2-different")
	mustReconcile(t, ra)
	res := mustReconcile(t, rb)
	if res.Downloaded != 1 {
		t.Fatalf("B downloaded = %d, want 1", res.Downloaded)
	}
	if got := treeOf(t, b)["f.txt"]; got != "v2-different" {
		t.Fatalf("B content = %q, want v2-different", got)
	}
}

func TestDeleteLocalPropagatesToRemote(t *testing.T) {
	prov := newProvider(t)
	a := t.TempDir()
	writeFile(t, a, "keep.txt", "k")
	writeFile(t, a, "drop.txt", "d")
	ra, _ := New(a, prov)
	mustReconcile(t, ra)

	// Mirror B has both.
	b := t.TempDir()
	rb, _ := New(b, prov)
	mustReconcile(t, rb)

	// Delete on A, reconcile A → remote loses it.
	if err := os.Remove(filepath.Join(a, "drop.txt")); err != nil {
		t.Fatal(err)
	}
	res := mustReconcile(t, ra)
	if res.DeletedRemote != 1 {
		t.Fatalf("deleted remote = %d, want 1", res.DeletedRemote)
	}
	// B pulls the deletion.
	res = mustReconcile(t, rb)
	if res.DeletedLocal != 1 {
		t.Fatalf("B deleted local = %d, want 1", res.DeletedLocal)
	}
	eqTree(t, treeOf(t, b), map[string]string{"keep.txt": "k"})
}

func TestDeleteRemotePropagatesToLocal(t *testing.T) {
	prov := newProvider(t)
	a := t.TempDir()
	writeFile(t, a, "x.txt", "x")
	ra, _ := New(a, prov)
	mustReconcile(t, ra)

	// Delete remotely by resolving the item via the provider.
	root, _ := prov.Root(context.Background())
	it, err := prov.Lookup(context.Background(), root, "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.DeleteItem(context.Background(), it.ID); err != nil {
		t.Fatal(err)
	}

	res := mustReconcile(t, ra)
	if res.DeletedLocal != 1 {
		t.Fatalf("deleted local = %d, want 1", res.DeletedLocal)
	}
	if pathExists(filepath.Join(a, "x.txt")) {
		t.Fatalf("x.txt still present locally after remote delete")
	}
}

func TestNoOpWhenInSync(t *testing.T) {
	prov := newProvider(t)
	local := t.TempDir()
	writeFile(t, local, "a.txt", "a")
	writeFile(t, local, "d/b.txt", "b")
	r, _ := New(local, prov)
	mustReconcile(t, r)

	// A second pass with no changes must plan nothing.
	plan, err := r.PlanOnly(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Fatalf("expected empty plan when in sync, got %d ops: %+v", len(plan.Ops), plan.Ops)
	}
	res := mustReconcile(t, r)
	if res.Uploaded+res.Downloaded+res.DeletedLocal+res.DeletedRemote != 0 {
		t.Fatalf("in-sync reconcile did work: %+v", res)
	}
}

func TestSymlinkRoundTrip(t *testing.T) {
	prov := newProvider(t)
	a := t.TempDir()
	writeFile(t, a, "target.txt", "data")
	symlink(t, a, "link", "target.txt")
	ra, _ := New(a, prov)
	mustReconcile(t, ra)

	b := t.TempDir()
	rb, _ := New(b, prov)
	mustReconcile(t, rb)
	tree := treeOf(t, b)
	if tree["link"] != "L:target.txt" {
		t.Fatalf("symlink not restored: %v", tree)
	}
	if tree["target.txt"] != "data" {
		t.Fatalf("target not restored: %v", tree)
	}
}

func TestConflictPreferLocal(t *testing.T) {
	prov := newProvider(t)
	a, b := t.TempDir(), t.TempDir()
	writeFile(t, a, "c.txt", "base")
	ra, _ := New(a, prov)
	rb, _ := New(b, prov)
	mustReconcile(t, ra) // seed remote
	mustReconcile(t, rb) // B gets base

	// Both edit independently.
	writeFile(t, b, "c.txt", "from-B")
	mustReconcile(t, rb) // remote now B's version
	writeFile(t, a, "c.txt", "from-A-wins")

	res := mustReconcile(t, ra) // A: remote changed + local changed → conflict, prefer local
	if res.Uploaded != 1 {
		t.Fatalf("expected 1 upload from conflict resolution, got %+v", res)
	}
	// B pulls A's winning version.
	mustReconcile(t, rb)
	if got := treeOf(t, b)["c.txt"]; got != "from-A-wins" {
		t.Fatalf("prefer-local did not win: B has %q", got)
	}
}

func TestConflictPreferRemote(t *testing.T) {
	prov := newProvider(t)
	a, b := t.TempDir(), t.TempDir()
	writeFile(t, a, "c.txt", "base")
	ra, _ := New(a, prov)
	rb, _ := New(b, prov, WithConflictPolicy(PreferRemote))
	mustReconcile(t, ra)
	mustReconcile(t, rb)

	writeFile(t, a, "c.txt", "remote-side")
	mustReconcile(t, ra) // remote now this
	writeFile(t, b, "c.txt", "local-side-loses")

	res := mustReconcile(t, rb) // B prefers remote
	if res.Downloaded != 1 {
		t.Fatalf("expected 1 download from conflict resolution, got %+v", res)
	}
	if got := treeOf(t, b)["c.txt"]; got != "remote-side" {
		t.Fatalf("prefer-remote did not win: B has %q", got)
	}
}

func TestConflictSkipPreservesBoth(t *testing.T) {
	prov := newProvider(t)
	a, b := t.TempDir(), t.TempDir()
	writeFile(t, a, "c.txt", "base")
	ra, _ := New(a, prov)
	rb, _ := New(b, prov, WithConflictPolicy(Skip))
	mustReconcile(t, ra)
	mustReconcile(t, rb)

	writeFile(t, a, "c.txt", "A-edit")
	mustReconcile(t, ra)
	writeFile(t, b, "c.txt", "B-edit")

	res := mustReconcile(t, rb)
	if res.Conflicts != 1 {
		t.Fatalf("expected 1 skipped conflict, got %+v", res)
	}
	// Neither side clobbered: B keeps its edit.
	if got := treeOf(t, b)["c.txt"]; got != "B-edit" {
		t.Fatalf("skip modified local: %q", got)
	}
	// The conflict must resurface (base preserved), not vanish.
	plan, _ := rb.PlanOnly(context.Background())
	if plan.Empty() {
		t.Fatalf("skipped conflict did not resurface on the next pass")
	}
}

func TestStateFileNotSynced(t *testing.T) {
	prov := newProvider(t)
	local := t.TempDir()
	writeFile(t, local, "a.txt", "a")
	r, _ := New(local, prov)
	mustReconcile(t, r)

	// The state sidecar must exist locally but never reach the remote tree.
	if !pathExists(filepath.Join(local, StateFileName)) {
		t.Fatalf("state file was not written")
	}
	remote, err := scanRemote(context.Background(), prov)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := remote[StateFileName]; ok {
		t.Fatalf("state sidecar leaked into the remote tree")
	}
}

func TestPlanOrderingParentsFirst(t *testing.T) {
	prov := newProvider(t)
	local := t.TempDir()
	writeFile(t, local, "deep/nested/file.txt", "x")
	r, _ := New(local, prov)
	plan, err := r.PlanOnly(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Every non-delete op's path must not appear after a deeper sibling; check
	// that parents are created before children by verifying depth is
	// non-decreasing across non-delete ops.
	last := -1
	for _, op := range plan.Ops {
		if isDelete(op.Kind) {
			continue
		}
		if depth(op.Path) < last {
			t.Fatalf("op %q (depth %d) ordered after a deeper op (last depth %d): %+v",
				op.Path, depth(op.Path), last, plan.Ops)
		}
		last = depth(op.Path)
	}
}
