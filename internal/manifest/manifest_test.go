package manifest

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"revika/internal/cap"
	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

func testConfig() pipeline.Config {
	// Small chunks exercise multi-chunk file data; manifest/dir blobs stay well
	// within one chunk (StoreBlob is single-chunk by contract).
	return pipeline.Config{ChunkSize: 4096, Params: erasure.Params{K: 4, M: 2}, Compress: true}
}

// storeFile runs data through the pipeline and stores its manifest as a KindFile
// blob, returning the file's read-cap.
func storeFile(t *testing.T, ctx context.Context, s store.Store, cfg pipeline.Config, name string, data []byte) ReadCap {
	t.Helper()
	fm, err := pipeline.StoreFile(ctx, s, cfg, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("StoreFile %s: %v", name, err)
	}
	fm.Name = name
	c, err := StoreFileManifest(ctx, s, cfg, fm)
	if err != nil {
		t.Fatalf("StoreFileManifest %s: %v", name, err)
	}
	if c.Kind != KindFile {
		t.Fatalf("cap kind = %s, want file", c.Kind)
	}
	return c
}

// loadFile reconstructs a file's bytes from its cap.
func loadFile(t *testing.T, ctx context.Context, s store.Store, c ReadCap) []byte {
	t.Helper()
	fm, err := LoadFileManifest(ctx, s, c)
	if err != nil {
		t.Fatalf("LoadFileManifest: %v", err)
	}
	var buf bytes.Buffer
	if err := pipeline.LoadFile(ctx, s, fm, &buf); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return buf.Bytes()
}

func mustStoreDir(t *testing.T, ctx context.Context, s store.Store, cfg pipeline.Config, d DirManifest) ReadCap {
	t.Helper()
	c, err := StoreDir(ctx, s, cfg, d)
	if err != nil {
		t.Fatalf("StoreDir: %v", err)
	}
	return c
}

// buildTree constructs a small namespace and returns its root cap plus the file
// caps for later comparison:
//
//	/notes.txt
//	/docs/a.txt
func buildTree(t *testing.T, ctx context.Context, s store.Store, cfg pipeline.Config) (root, notes, aTxt ReadCap) {
	t.Helper()
	notes = storeFile(t, ctx, s, cfg, "notes.txt", []byte("top-level notes"))
	aTxt = storeFile(t, ctx, s, cfg, "a.txt", bytes.Repeat([]byte("A"), 9000))

	docs := NewDir(pipeline.Metadata{}).
		Upsert(Entry{Name: "a.txt", Cap: aTxt, Stat: StatCache{Kind: KindFile, Size: 9000}})
	docsCap := mustStoreDir(t, ctx, s, cfg, docs)

	rootDir := NewDir(pipeline.Metadata{}).
		Upsert(Entry{Name: "notes.txt", Cap: notes, Stat: StatCache{Kind: KindFile, Size: 15}}).
		Upsert(Entry{Name: "docs", Cap: docsCap, Stat: StatCache{Kind: KindDir}})
	root = mustStoreDir(t, ctx, s, cfg, rootDir)
	return root, notes, aTxt
}

func TestFileManifestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	want := bytes.Repeat([]byte("revika"), 5000)

	c := storeFile(t, ctx, s, cfg, "big.bin", want)
	if got := loadFile(t, ctx, s, c); !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, notes, aTxt := buildTree(t, ctx, s, cfg)

	cases := map[string]ReadCap{
		"":           root,
		"notes.txt":  notes,
		"docs":       {}, // filled below
		"docs/a.txt": aTxt,
	}
	// The docs cap is whatever the root records for it.
	rootDir, err := LoadDir(ctx, s, root)
	if err != nil {
		t.Fatal(err)
	}
	docsEntry, _ := rootDir.Lookup("docs")
	cases["docs"] = docsEntry.Cap

	for p, want := range cases {
		got, err := Resolve(ctx, s, root, p)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", p, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Resolve(%q) cap mismatch", p)
		}
	}

	// The resolved file cap really reads back its content.
	if got := loadFile(t, ctx, s, aTxt); !bytes.Equal(got, bytes.Repeat([]byte("A"), 9000)) {
		t.Fatal("docs/a.txt content mismatch")
	}

	// Missing paths and non-directory descents fail cleanly.
	if _, err := Resolve(ctx, s, root, "docs/missing.txt"); err == nil {
		t.Fatal("Resolve of missing path should fail")
	}
	if _, err := Resolve(ctx, s, root, "notes.txt/nope"); err == nil {
		t.Fatal("descending into a file should fail")
	}
	if _, err := Resolve(ctx, s, root, "../escape"); err == nil {
		t.Fatal("path escaping the root should fail")
	}
}

func TestResolveEntry(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, _, aTxt := buildTree(t, ctx, s, cfg)

	// A leaf carries both its cap and the parent's cached stat.
	e, err := ResolveEntry(ctx, s, root, "docs/a.txt")
	if err != nil {
		t.Fatalf("ResolveEntry(docs/a.txt): %v", err)
	}
	if !reflect.DeepEqual(e.Cap, aTxt) {
		t.Fatal("ResolveEntry cap mismatch for docs/a.txt")
	}
	if e.Name != "a.txt" || e.Stat.Kind != KindFile || e.Stat.Size != 9000 {
		t.Fatalf("ResolveEntry stat = %+v, want name a.txt, file, size 9000", e)
	}

	// A subdirectory reports its cap and dir stat.
	de, err := ResolveEntry(ctx, s, root, "docs")
	if err != nil {
		t.Fatalf("ResolveEntry(docs): %v", err)
	}
	if de.Name != "docs" || de.Stat.Kind != KindDir {
		t.Fatalf("ResolveEntry(docs) = %+v, want dir named docs", de)
	}

	// The root itself has no parent entry: a nameless dir carrying the root cap.
	re, err := ResolveEntry(ctx, s, root, "")
	if err != nil {
		t.Fatalf("ResolveEntry(root): %v", err)
	}
	if re.Name != "" || re.Stat.Kind != KindDir || !reflect.DeepEqual(re.Cap, root) {
		t.Fatalf("ResolveEntry(root) = %+v, want nameless dir with the root cap", re)
	}

	// Missing paths and descending into a file fail cleanly (as Resolve does).
	if _, err := ResolveEntry(ctx, s, root, "docs/missing.txt"); err == nil {
		t.Fatal("ResolveEntry of missing path should fail")
	}
	if _, err := ResolveEntry(ctx, s, root, "notes.txt/nope"); err == nil {
		t.Fatal("descending into a file should fail")
	}
}

func TestGraftCopyOnWrite(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, notes, _ := buildTree(t, ctx, s, cfg)

	bTxt := storeFile(t, ctx, s, cfg, "b.txt", []byte("brand new file"))
	newRoot, err := Graft(ctx, s, cfg, root, "docs/b.txt", bTxt, StatCache{Size: 14})
	if err != nil {
		t.Fatalf("Graft: %v", err)
	}

	// New file resolves under the new root.
	got, err := Resolve(ctx, s, newRoot, "docs/b.txt")
	if err != nil || !reflect.DeepEqual(got, bTxt) {
		t.Fatalf("Resolve new file: got %v err %v", got, err)
	}
	if b := loadFile(t, ctx, s, got); !bytes.Equal(b, []byte("brand new file")) {
		t.Fatal("new file content mismatch")
	}

	// Sibling still present under the new root.
	if _, err := Resolve(ctx, s, newRoot, "docs/a.txt"); err != nil {
		t.Fatalf("sibling a.txt lost after graft: %v", err)
	}

	// Old root is immutable: it never learned about b.txt.
	if _, err := Resolve(ctx, s, root, "docs/b.txt"); err == nil {
		t.Fatal("old root should not resolve b.txt")
	}

	// Structural sharing: an untouched subtree keeps the exact same cap
	// (same key + shard IDs), so no bytes were rewritten for it.
	oldNotes, _ := Resolve(ctx, s, root, "notes.txt")
	newNotes, _ := Resolve(ctx, s, newRoot, "notes.txt")
	if !reflect.DeepEqual(oldNotes, newNotes) || !reflect.DeepEqual(newNotes, notes) {
		t.Fatal("untouched notes.txt cap changed across a graft")
	}
}

func TestGraftCreatesIntermediateDirs(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, _, _ := buildTree(t, ctx, s, cfg)

	x := storeFile(t, ctx, s, cfg, "x.txt", []byte("deep"))
	newRoot, err := Graft(ctx, s, cfg, root, "new/deep/here/x.txt", x, StatCache{Size: 4})
	if err != nil {
		t.Fatalf("Graft deep: %v", err)
	}
	got, err := Resolve(ctx, s, newRoot, "new/deep/here/x.txt")
	if err != nil {
		t.Fatalf("Resolve deep: %v", err)
	}
	if !reflect.DeepEqual(got, x) {
		t.Fatal("deep cap mismatch")
	}
	// An auto-created intermediate is a directory.
	mid, err := Resolve(ctx, s, newRoot, "new/deep")
	if err != nil || mid.Kind != KindDir {
		t.Fatalf("intermediate should be a dir: kind=%s err=%v", mid.Kind, err)
	}
}

func TestGraftRemove(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, _, _ := buildTree(t, ctx, s, cfg)

	pruned, err := GraftRemove(ctx, s, cfg, root, "docs/a.txt")
	if err != nil {
		t.Fatalf("GraftRemove: %v", err)
	}
	if _, err := Resolve(ctx, s, pruned, "docs/a.txt"); err == nil {
		t.Fatal("removed entry still resolves")
	}
	// The parent directory survives, just emptied of that child.
	if _, err := Resolve(ctx, s, pruned, "docs"); err != nil {
		t.Fatalf("docs dir lost: %v", err)
	}
	// Old root still has it (immutability).
	if _, err := Resolve(ctx, s, root, "docs/a.txt"); err != nil {
		t.Fatalf("old root lost a.txt: %v", err)
	}
	// Removing something absent errors.
	if _, err := GraftRemove(ctx, s, cfg, root, "docs/ghost"); err == nil {
		t.Fatal("removing an absent entry should fail")
	}
}

func TestKindMismatch(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	fileCap := storeFile(t, ctx, s, cfg, "f.txt", []byte("hi"))

	if _, err := LoadDir(ctx, s, fileCap); err == nil {
		t.Fatal("LoadDir on a file cap should fail")
	}
	dirCap := mustStoreDir(t, ctx, s, cfg, NewDir(pipeline.Metadata{}))
	if _, err := LoadFileManifest(ctx, s, dirCap); err == nil {
		t.Fatal("LoadFileManifest on a dir cap should fail")
	}
}

func TestWrapCapRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, _, _ := buildTree(t, ctx, s, cfg)

	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := WrapCap(pub, root)
	if err != nil {
		t.Fatalf("WrapCap: %v", err)
	}
	got, err := UnwrapCap(priv, pub, sealed)
	if err != nil {
		t.Fatalf("UnwrapCap: %v", err)
	}
	if !reflect.DeepEqual(got, root) {
		t.Fatal("unwrapped cap != original")
	}

	// A recipient holding the wrong key cannot unwrap — and the recovered cap
	// still resolves the whole shared subtree for the right recipient.
	otherPriv, _, _ := cap.GenerateIdentity()
	if _, err := UnwrapCap(otherPriv, pub, sealed); err == nil {
		t.Fatal("unwrap with wrong key should fail")
	}
	if _, err := Resolve(ctx, s, got, "docs/a.txt"); err != nil {
		t.Fatalf("shared subtree not resolvable by recipient: %v", err)
	}
}

func TestRootPointerSignVerify(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemStore()
	cfg := testConfig()
	root, _, _ := buildTree(t, ctx, s, cfg)

	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := SignRoot(sk, root, 1, 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	if !rp.Verify() {
		t.Fatal("freshly signed root pointer should verify")
	}
	if rp.Owner != sk.Public() {
		t.Fatal("owner should be the signer's public key")
	}

	// Tampering with any signed field breaks verification.
	bad := rp
	bad.Seq = 2
	if bad.Verify() {
		t.Fatal("bumped Seq should not verify under the old signature")
	}
	bad = rp
	bad.Root.Kind = KindFile
	if bad.Verify() {
		t.Fatal("altered root cap should not verify")
	}

	// A later, legitimately re-signed pointer advances the sequence — the anchor
	// a reader keeps over the old one.
	rp2, err := SignRoot(sk, root, 2, 1_700_000_001_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !rp2.Verify() || rp2.Seq <= rp.Seq {
		t.Fatal("re-signed pointer should verify and advance Seq")
	}
}

func TestEncodeDirDeterministic(t *testing.T) {
	// Entry insertion order must not affect the serialized bytes — canonical
	// encoding is what keeps a directory idempotent and its cap meaningful.
	d1 := NewDir(pipeline.Metadata{Mode: 0o755}).
		Upsert(Entry{Name: "b", Stat: StatCache{Kind: KindFile}}).
		Upsert(Entry{Name: "a", Stat: StatCache{Kind: KindFile}}).
		Upsert(Entry{Name: "c", Stat: StatCache{Kind: KindDir}})
	d2 := NewDir(pipeline.Metadata{Mode: 0o755}).
		Upsert(Entry{Name: "c", Stat: StatCache{Kind: KindDir}}).
		Upsert(Entry{Name: "a", Stat: StatCache{Kind: KindFile}}).
		Upsert(Entry{Name: "b", Stat: StatCache{Kind: KindFile}})

	b1, err := EncodeDir(d1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := EncodeDir(d2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("EncodeDir not order-independent:\n%s\n---\n%s", b1, b2)
	}

	// And it round-trips.
	got, err := DecodeDir(b1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 3 || got.Entries[0].Name != "a" || got.Entries[2].Name != "c" {
		t.Fatalf("decoded entries wrong: %+v", got.Entries)
	}
}
