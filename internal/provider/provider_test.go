package provider

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"strings"
	"testing"

	"revika/internal/cap"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// newTestProvider builds a Manifest provider over a fresh MemStore with a fixed
// clock, so signed root pointers are deterministic across runs.
func newTestProvider(t *testing.T) (*Manifest, context.Context) {
	t.Helper()
	ctx := context.Background()
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	var tick int64
	p, err := New(ctx, store.NewMemStore(), sk, NewMemRootStore(), WithClock(func() int64 {
		tick++
		return tick
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, ctx
}

func create(t *testing.T, p *Manifest, ctx context.Context, parent ItemID, name string, body string) Item {
	t.Helper()
	it, err := p.CreateItem(ctx, parent, CreateRequest{
		Name:     name,
		Meta:     pipeline.Metadata{Mode: 0o644},
		Contents: strings.NewReader(body),
	})
	if err != nil {
		t.Fatalf("CreateItem %q: %v", name, err)
	}
	return it
}

func mkdir(t *testing.T, p *Manifest, ctx context.Context, parent ItemID, name string) Item {
	t.Helper()
	it, err := p.CreateItem(ctx, parent, CreateRequest{
		Name:  name,
		IsDir: true,
		Meta:  pipeline.Metadata{Mode: dirMode()},
	})
	if err != nil {
		t.Fatalf("CreateItem dir %q: %v", name, err)
	}
	return it
}

func fetch(t *testing.T, p *Manifest, ctx context.Context, id ItemID) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := p.FetchContents(ctx, id, &buf); err != nil {
		t.Fatalf("FetchContents: %v", err)
	}
	return buf.String()
}

// TestCreateEnumerateFetch covers the core loop: create files and a directory,
// enumerate, and hydrate content back out.
func TestCreateEnumerateFetch(t *testing.T) {
	p, ctx := newTestProvider(t)

	root, err := p.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if root != RootID {
		t.Fatalf("Root = %q, want %q", root, RootID)
	}

	a := create(t, p, ctx, RootID, "a.txt", "hello")
	dir := mkdir(t, p, ctx, RootID, "sub")
	create(t, p, ctx, dir.ID, "b.txt", "world")

	items, err := p.Enumerate(ctx, RootID)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("root has %d items, want 2", len(items))
	}

	names := map[string]Item{}
	for _, it := range items {
		names[it.Name] = it
	}
	if _, ok := names["a.txt"]; !ok {
		t.Fatal("a.txt missing from enumeration")
	}
	if d, ok := names["sub"]; !ok || !d.IsDir {
		t.Fatal("sub directory missing or not a dir")
	}
	if !names["sub"].Caps.Has(CapEnumerate) || !names["sub"].Caps.Has(CapAddSubItems) {
		t.Error("directory lacks enumerate/add-subitem caps")
	}

	if got := fetch(t, p, ctx, a.ID); got != "hello" {
		t.Errorf("a.txt content = %q, want hello", got)
	}

	sub, err := p.Enumerate(ctx, dir.ID)
	if err != nil {
		t.Fatalf("Enumerate sub: %v", err)
	}
	if len(sub) != 1 || sub[0].Name != "b.txt" {
		t.Fatalf("sub enumeration = %+v", sub)
	}
	if got := fetch(t, p, ctx, sub[0].ID); got != "world" {
		t.Errorf("b.txt content = %q, want world", got)
	}
}

// TestLookupAndStat checks name resolution and that Stat returns the full record.
func TestLookupAndStat(t *testing.T) {
	p, ctx := newTestProvider(t)
	created := create(t, p, ctx, RootID, "doc.txt", "abcdef")

	got, err := p.Lookup(ctx, RootID, "doc.txt")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("Lookup ID = %q, want %q", got.ID, created.ID)
	}

	st, err := p.Stat(ctx, created.ID)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Size != 6 {
		t.Errorf("Stat size = %d, want 6", st.Size)
	}
	if st.Meta.Mode != 0o644 {
		t.Errorf("Stat mode = %o, want 644", st.Meta.Mode)
	}

	if _, err := p.Lookup(ctx, RootID, "missing"); err != ErrNotFound {
		t.Errorf("Lookup missing err = %v, want ErrNotFound", err)
	}
}

// TestModifyVersions checks that a content edit bumps ContentVersion and that a
// metadata-only edit bumps MetaVersion while keeping ContentVersion stable — the
// distinction the frameworks rely on.
func TestModifyVersions(t *testing.T) {
	p, ctx := newTestProvider(t)
	it := create(t, p, ctx, RootID, "f", "one")
	v0 := it.Version

	edited, err := p.ModifyItem(ctx, it.ID, ModifyRequest{Contents: strings.NewReader("two-and-more")})
	if err != nil {
		t.Fatalf("ModifyItem content: %v", err)
	}
	if bytes.Equal(edited.Version.Content, v0.Content) {
		t.Error("ContentVersion unchanged after content edit")
	}
	if got := fetch(t, p, ctx, it.ID); got != "two-and-more" {
		t.Errorf("content after edit = %q", got)
	}

	mode := pipeline.Metadata{Mode: 0o600, ModTimeNS: 42}
	metaOnly, err := p.ModifyItem(ctx, it.ID, ModifyRequest{Meta: &mode})
	if err != nil {
		t.Fatalf("ModifyItem meta: %v", err)
	}
	if !bytes.Equal(metaOnly.Version.Content, edited.Version.Content) {
		t.Error("ContentVersion changed after metadata-only edit")
	}
	if bytes.Equal(metaOnly.Version.Meta, edited.Version.Meta) {
		t.Error("MetaVersion unchanged after metadata-only edit")
	}
}

// TestRenameStableID checks an item keeps its ID across a rename and a reparent,
// and that its content follows.
func TestRenameStableID(t *testing.T) {
	p, ctx := newTestProvider(t)
	it := create(t, p, ctx, RootID, "old.txt", "payload")
	dir := mkdir(t, p, ctx, RootID, "box")

	// Rename in place.
	renamed, err := p.Rename(ctx, it.ID, RootID, "new.txt")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.ID != it.ID {
		t.Errorf("ID changed on rename: %q -> %q", it.ID, renamed.ID)
	}
	if renamed.Name != "new.txt" {
		t.Errorf("name = %q, want new.txt", renamed.Name)
	}
	if _, err := p.Lookup(ctx, RootID, "old.txt"); err != ErrNotFound {
		t.Error("old name still resolves after rename")
	}

	// Reparent into box/.
	moved, err := p.Rename(ctx, it.ID, dir.ID, "new.txt")
	if err != nil {
		t.Fatalf("Rename reparent: %v", err)
	}
	if moved.ID != it.ID {
		t.Errorf("ID changed on reparent: %q -> %q", it.ID, moved.ID)
	}
	if moved.Parent != dir.ID {
		t.Errorf("parent = %q, want %q", moved.Parent, dir.ID)
	}
	if got := fetch(t, p, ctx, it.ID); got != "payload" {
		t.Errorf("content after reparent = %q", got)
	}
}

// TestDeleteRetiresID checks a deleted item stops resolving and a recreation
// under the same name gets a fresh ID (a new item, per the frameworks).
func TestDeleteRetiresID(t *testing.T) {
	p, ctx := newTestProvider(t)
	it := create(t, p, ctx, RootID, "gone.txt", "x")

	if err := p.DeleteItem(ctx, it.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if _, err := p.Stat(ctx, it.ID); err != ErrNotFound {
		t.Errorf("Stat after delete err = %v, want ErrNotFound", err)
	}
	if _, err := p.Lookup(ctx, RootID, "gone.txt"); err != ErrNotFound {
		t.Error("deleted name still resolves")
	}

	again := create(t, p, ctx, RootID, "gone.txt", "y")
	if again.ID == it.ID {
		t.Error("recreated item reused the retired ID")
	}
}

// TestEnumerateChanges checks the delta stream against an anchor: adds,
// modifications, and deletes, with unchanged subtrees pruned.
func TestEnumerateChanges(t *testing.T) {
	p, ctx := newTestProvider(t)
	a := create(t, p, ctx, RootID, "a.txt", "a")
	create(t, p, ctx, RootID, "keep.txt", "keep")

	anchor, err := p.CurrentAnchor(ctx)
	if err != nil {
		t.Fatalf("CurrentAnchor: %v", err)
	}

	// Mutate: edit a, add c, delete nothing yet.
	if _, err := p.ModifyItem(ctx, a.ID, ModifyRequest{Contents: strings.NewReader("aaa")}); err != nil {
		t.Fatalf("ModifyItem: %v", err)
	}
	c := create(t, p, ctx, RootID, "c.txt", "c")

	cs, err := p.EnumerateChanges(ctx, anchor)
	if err != nil {
		t.Fatalf("EnumerateChanges: %v", err)
	}
	byPath := map[string]Change{}
	for _, ch := range cs.Changes {
		byPath[ch.Path] = ch
	}
	if ch, ok := byPath["a.txt"]; !ok || ch.Type != ChangeModified {
		t.Errorf("a.txt change = %+v (want modified)", ch)
	}
	if ch, ok := byPath["c.txt"]; !ok || ch.Type != ChangeAdded {
		t.Errorf("c.txt change = %+v (want added)", ch)
	}
	if _, ok := byPath["keep.txt"]; ok {
		t.Error("unchanged keep.txt appeared in the delta")
	}

	// Now delete c and diff against the new anchor.
	anchor2 := cs.Anchor
	if err := p.DeleteItem(ctx, c.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	cs2, err := p.EnumerateChanges(ctx, anchor2)
	if err != nil {
		t.Fatalf("EnumerateChanges 2: %v", err)
	}
	if len(cs2.Changes) != 1 || cs2.Changes[0].Type != ChangeDeleted || cs2.Changes[0].Path != "c.txt" {
		t.Errorf("delete delta = %+v", cs2.Changes)
	}
}

// TestSymlinkRoundTrip checks a symlink is stored as metadata (no content shards)
// and reported as a link.
func TestSymlinkRoundTrip(t *testing.T) {
	p, ctx := newTestProvider(t)
	it, err := p.CreateItem(ctx, RootID, CreateRequest{
		Name: "link",
		Meta: pipeline.Metadata{Mode: uint32(fs.ModeSymlink | 0o777), SymlinkTarget: "/etc/hostname"},
	})
	if err != nil {
		t.Fatalf("CreateItem symlink: %v", err)
	}
	if !it.IsLink {
		t.Error("item not reported as a link")
	}
	st, err := p.Stat(ctx, it.ID)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Meta.SymlinkTarget != "/etc/hostname" {
		t.Errorf("symlink target = %q", st.Meta.SymlinkTarget)
	}
	// Fetching a symlink streams nothing.
	if got := fetch(t, p, ctx, it.ID); got != "" {
		t.Errorf("symlink fetch returned %q, want empty", got)
	}
}

// TestPersistenceAcrossReopen checks a second Manifest over the same store and
// root store adopts the published root pointer (the anti-rollback anchor).
func TestPersistenceAcrossReopen(t *testing.T) {
	ctx := context.Background()
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	s := store.NewMemStore()
	roots := NewMemRootStore()
	var tick int64
	clock := WithClock(func() int64 { tick++; return tick })

	p1, err := New(ctx, s, sk, roots, clock)
	if err != nil {
		t.Fatalf("New p1: %v", err)
	}
	create(t, p1, ctx, RootID, "persist.txt", "data")

	p2, err := New(ctx, s, sk, roots, clock)
	if err != nil {
		t.Fatalf("New p2: %v", err)
	}
	got, err := p2.Lookup(ctx, RootID, "persist.txt")
	if err != nil {
		t.Fatalf("Lookup after reopen: %v", err)
	}
	var buf bytes.Buffer
	if _, err := p2.FetchContents(ctx, got.ID, &buf); err != nil {
		t.Fatalf("FetchContents after reopen: %v", err)
	}
	if buf.String() != "data" {
		t.Errorf("content after reopen = %q", buf.String())
	}
}

var _ io.Reader = strings.NewReader("")
