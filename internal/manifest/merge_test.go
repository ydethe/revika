package manifest

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"revika/internal/pipeline"
	"revika/internal/store"
)

// resolveNames returns the sorted child names of the directory at path p under
// root, or fails the test. It lets a merge assertion talk about structure without
// caring about the fresh keys a re-stored directory carries.
func resolveNames(t *testing.T, ctx context.Context, s store.Store, root ReadCap, p string) []string {
	t.Helper()
	c, err := Resolve(ctx, s, root, p)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", p, err)
	}
	d, err := LoadDir(ctx, s, c)
	if err != nil {
		t.Fatalf("LoadDir(%q): %v", p, err)
	}
	names := make([]string, len(d.Entries))
	for i, e := range d.Entries {
		names[i] = e.Name
	}
	slices.Sort(names)
	return names
}

// resolveMissing asserts that path p does not resolve under root.
func resolveMissing(t *testing.T, ctx context.Context, s store.Store, root ReadCap, p string) {
	t.Helper()
	if _, err := Resolve(ctx, s, root, p); err == nil {
		t.Fatalf("expected %q to be absent, but it resolved", p)
	}
}

// TestMerge3DisjointEdits merges a notes.txt edit on one side with a new file in
// docs on the other: both land, nothing conflicts.
func TestMerge3DisjointEdits(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	base, _, _ := buildTree(t, ctx, s, cfg)

	newNotes := storeFile(t, ctx, s, cfg, "notes.txt", []byte("edited notes"))
	local, err := Graft(ctx, s, cfg, base, "notes.txt", newNotes, StatCache{Size: 12})
	if err != nil {
		t.Fatal(err)
	}

	bTxt := storeFile(t, ctx, s, cfg, "b.txt", []byte("brand new"))
	remote, err := Graft(ctx, s, cfg, base, "docs/b.txt", bTxt, StatCache{Size: 9})
	if err != nil {
		t.Fatal(err)
	}

	merged, conflicts, err := Merge3(ctx, s, cfg, base, local, remote, nil)
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("disjoint edits should not conflict, got %v", conflicts)
	}
	// The local notes edit survived.
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged, "notes.txt")); !bytes.Equal(got, []byte("edited notes")) {
		t.Fatal("local notes edit lost")
	}
	// Both docs children are present.
	if names := resolveNames(t, ctx, s, merged, "docs"); !slices.Equal(names, []string{"a.txt", "b.txt"}) {
		t.Fatalf("docs = %v, want [a.txt b.txt]", names)
	}
}

// TestMerge3SamePathConflict has both sides edit notes.txt to different bytes:
// local keeps its name, remote is filed under the labeled conflict copy.
func TestMerge3SamePathConflict(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	base, _, _ := buildTree(t, ctx, s, cfg)

	localNotes := storeFile(t, ctx, s, cfg, "notes.txt", []byte("local wins its name"))
	local, err := Graft(ctx, s, cfg, base, "notes.txt", localNotes, StatCache{})
	if err != nil {
		t.Fatal(err)
	}
	remoteNotes := storeFile(t, ctx, s, cfg, "notes.txt", []byte("remote is a copy"))
	remote, err := Graft(ctx, s, cfg, base, "notes.txt", remoteNotes, StatCache{})
	if err != nil {
		t.Fatal(err)
	}

	merged, conflicts, err := Merge3(ctx, s, cfg, base, local, remote, nil)
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if !slices.Equal(conflicts, []string{"notes.txt"}) {
		t.Fatalf("conflicts = %v, want [notes.txt]", conflicts)
	}
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged, "notes.txt")); !bytes.Equal(got, []byte("local wins its name")) {
		t.Fatal("local edit should keep the original name")
	}
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged, "notes (conflict).txt")); !bytes.Equal(got, []byte("remote is a copy")) {
		t.Fatal("remote edit should be filed as the conflict copy")
	}
}

// TestMerge3DeleteVsEdit checks that a delete racing an edit keeps the edit and
// reports the conflict — in both directions.
func TestMerge3DeleteVsEdit(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	base, _, _ := buildTree(t, ctx, s, cfg)

	// local deletes docs/a.txt; remote edits it.
	localDel, err := GraftRemove(ctx, s, cfg, base, "docs/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	editedA := storeFile(t, ctx, s, cfg, "a.txt", []byte("remote kept editing"))
	remoteEdit, err := Graft(ctx, s, cfg, base, "docs/a.txt", editedA, StatCache{})
	if err != nil {
		t.Fatal(err)
	}

	merged, conflicts, err := Merge3(ctx, s, cfg, base, localDel, remoteEdit, nil)
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if !slices.Equal(conflicts, []string{"docs/a.txt"}) {
		t.Fatalf("conflicts = %v, want [docs/a.txt]", conflicts)
	}
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged, "docs/a.txt")); !bytes.Equal(got, []byte("remote kept editing")) {
		t.Fatal("edit should win over a racing delete")
	}

	// Symmetric: local edits, remote deletes — the edit still wins.
	merged2, conflicts2, err := Merge3(ctx, s, cfg, base, remoteEdit, localDel, nil)
	if err != nil {
		t.Fatalf("Merge3 reversed: %v", err)
	}
	if !slices.Equal(conflicts2, []string{"docs/a.txt"}) {
		t.Fatalf("reversed conflicts = %v, want [docs/a.txt]", conflicts2)
	}
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged2, "docs/a.txt")); !bytes.Equal(got, []byte("remote kept editing")) {
		t.Fatal("edit should win over a racing delete (reversed)")
	}
}

// TestMerge3DeleteVsUnchanged confirms a clean delete propagates when the other
// side left that entry alone (but changed something else, so the merge recurses
// rather than short-circuiting the whole tree).
func TestMerge3DeleteVsUnchanged(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	base, _, _ := buildTree(t, ctx, s, cfg)

	localDel, err := GraftRemove(ctx, s, cfg, base, "docs/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	newNotes := storeFile(t, ctx, s, cfg, "notes.txt", []byte("unrelated edit"))
	remote, err := Graft(ctx, s, cfg, base, "notes.txt", newNotes, StatCache{})
	if err != nil {
		t.Fatal(err)
	}

	merged, conflicts, err := Merge3(ctx, s, cfg, base, localDel, remote, nil)
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("delete vs untouched should not conflict, got %v", conflicts)
	}
	resolveMissing(t, ctx, s, merged, "docs/a.txt") // delete propagated
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged, "notes.txt")); !bytes.Equal(got, []byte("unrelated edit")) {
		t.Fatal("unrelated remote edit lost")
	}
}

// TestMerge3DirFileSwap has one side replace a directory with a file while the
// other edits inside that directory: a conflict copy preserves both shapes.
func TestMerge3DirFileSwap(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	base, _, _ := buildTree(t, ctx, s, cfg)

	// local turns /docs into a file.
	docsAsFile := storeFile(t, ctx, s, cfg, "docs", []byte("now I am a file"))
	local, err := Graft(ctx, s, cfg, base, "docs", docsAsFile, StatCache{})
	if err != nil {
		t.Fatal(err)
	}
	// remote edits inside /docs, keeping it a directory.
	editedA := storeFile(t, ctx, s, cfg, "a.txt", []byte("still a dir over here"))
	remote, err := Graft(ctx, s, cfg, base, "docs/a.txt", editedA, StatCache{})
	if err != nil {
		t.Fatal(err)
	}

	merged, conflicts, err := Merge3(ctx, s, cfg, base, local, remote, nil)
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if !slices.Equal(conflicts, []string{"docs"}) {
		t.Fatalf("conflicts = %v, want [docs]", conflicts)
	}
	// Local's file kept the name; remote's directory is the conflict copy.
	if c := resolveCap(t, ctx, s, merged, "docs"); c.Kind != KindFile {
		t.Fatalf("docs kind = %s, want file", c.Kind)
	}
	if c := resolveCap(t, ctx, s, merged, "docs (conflict)"); c.Kind != KindDir {
		t.Fatalf("docs (conflict) kind = %s, want dir", c.Kind)
	}
	if got := loadFile(t, ctx, s, resolveCap(t, ctx, s, merged, "docs (conflict)/a.txt")); !bytes.Equal(got, []byte("still a dir over here")) {
		t.Fatal("remote directory content missing from conflict copy")
	}
}

// TestMerge3Deterministic runs the same merge twice and confirms the structure
// and contents match (the caps differ because re-stored dirs take fresh keys, so
// we compare what resolves, not the raw caps).
func TestMerge3Deterministic(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	base, _, _ := buildTree(t, ctx, s, cfg)

	la := storeFile(t, ctx, s, cfg, "notes.txt", []byte("L"))
	local, err := Graft(ctx, s, cfg, base, "notes.txt", la, StatCache{})
	if err != nil {
		t.Fatal(err)
	}
	ra := storeFile(t, ctx, s, cfg, "notes.txt", []byte("R"))
	remote, err := Graft(ctx, s, cfg, base, "notes.txt", ra, StatCache{})
	if err != nil {
		t.Fatal(err)
	}

	m1, c1, err := Merge3(ctx, s, cfg, base, local, remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	m2, c2, err := Merge3(ctx, s, cfg, base, local, remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c1, c2) {
		t.Fatalf("conflict lists differ across runs: %v vs %v", c1, c2)
	}
	if a, b := resolveNames(t, ctx, s, m1, ""), resolveNames(t, ctx, s, m2, ""); !slices.Equal(a, b) {
		t.Fatalf("root structure differs across runs: %v vs %v", a, b)
	}
}

// TestMerge3NoCommonAncestor merges two roots with a zero base: shared-name
// entries that differ still conflict, distinct entries all survive.
func TestMerge3NoCommonAncestor(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()

	lf := storeFile(t, ctx, s, cfg, "shared.txt", []byte("left"))
	localOnly := storeFile(t, ctx, s, cfg, "left.txt", []byte("only left"))
	local := mustStoreDir(t, ctx, s, cfg, NewDir(pipeline.Metadata{}).
		Upsert(Entry{Name: "shared.txt", Cap: lf, Stat: StatCache{Kind: KindFile}}).
		Upsert(Entry{Name: "left.txt", Cap: localOnly, Stat: StatCache{Kind: KindFile}}))

	rf := storeFile(t, ctx, s, cfg, "shared.txt", []byte("right"))
	remoteOnly := storeFile(t, ctx, s, cfg, "right.txt", []byte("only right"))
	remote := mustStoreDir(t, ctx, s, cfg, NewDir(pipeline.Metadata{}).
		Upsert(Entry{Name: "shared.txt", Cap: rf, Stat: StatCache{Kind: KindFile}}).
		Upsert(Entry{Name: "right.txt", Cap: remoteOnly, Stat: StatCache{Kind: KindFile}}))

	merged, conflicts, err := Merge3(ctx, s, cfg, ReadCap{}, local, remote, nil)
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if !slices.Equal(conflicts, []string{"shared.txt"}) {
		t.Fatalf("conflicts = %v, want [shared.txt]", conflicts)
	}
	if names := resolveNames(t, ctx, s, merged, ""); !slices.Equal(names, []string{"left.txt", "right.txt", "shared (conflict).txt", "shared.txt"}) {
		t.Fatalf("root = %v", names)
	}
}

// resolveCap resolves p under root to a cap or fails.
func resolveCap(t *testing.T, ctx context.Context, s store.Store, root ReadCap, p string) ReadCap {
	t.Helper()
	c, err := Resolve(ctx, s, root, p)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", p, err)
	}
	return c
}
