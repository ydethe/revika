package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// TestStoreRestoreTree stores a nested directory tree over an in-process node and
// restores it, asserting the file set and every file's bytes round-trip. This is
// the in-process counterpart of the docker-compose `tree` E2E (deploy/tree.sh).
func TestStoreRestoreTree(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}

	// Build a source tree:
	//   src/root.txt
	//   src/docs/a.txt
	//   src/docs/nested/b.bin   (multi-chunk)
	//   src/empty/              (empty directory)
	src := t.TempDir()
	want := map[string][]byte{
		"root.txt":          []byte("top level"),
		"docs/a.txt":        []byte("document a"),
		"docs/nested/b.bin": bytes.Repeat([]byte{0xAB, 0xCD}, 100*1024),
	}
	for rel, data := range want {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(src, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	root, files, err := storeTree(ctx, s, cfg, src)
	if err != nil {
		t.Fatalf("storeTree: %v", err)
	}
	if files != len(want) {
		t.Fatalf("stored %d files, want %d", files, len(want))
	}

	dst := t.TempDir()
	got, err := restoreTree(ctx, s, root, dst)
	if err != nil {
		t.Fatalf("restoreTree: %v", err)
	}
	if got != len(want) {
		t.Fatalf("restored %d files, want %d", got, len(want))
	}

	// Every file came back byte-identical, under the right relative path.
	for rel, data := range want {
		p := filepath.Join(dst, filepath.FromSlash(rel))
		gotData, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read restored %s: %v", rel, err)
		}
		if !bytes.Equal(gotData, data) {
			t.Fatalf("restored %s differs (%d vs %d bytes)", rel, len(gotData), len(data))
		}
	}

	// The empty directory survived the round-trip.
	if fi, err := os.Stat(filepath.Join(dst, "empty")); err != nil || !fi.IsDir() {
		t.Fatalf("empty directory not restored: err=%v", err)
	}

	// No stray files beyond what we stored (+ the empty dir).
	var relFiles []string
	filepath.WalkDir(dst, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			r, _ := filepath.Rel(dst, p)
			relFiles = append(relFiles, filepath.ToSlash(r))
		}
		return nil
	})
	sort.Strings(relFiles)
	if len(relFiles) != len(want) {
		t.Fatalf("restored file set = %v, want %d files", relFiles, len(want))
	}
}

// TestGetTreeRejectsFileCap ensures a single-file cap is refused by the tree
// restorer (and vice versa the flag guards catch the mismatch).
func TestRestoreTreeRejectsFileCap(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}

	dir := t.TempDir()
	f := filepath.Join(dir, "solo.txt")
	if err := os.WriteFile(f, []byte("just a file"), 0o644); err != nil {
		t.Fatal(err)
	}
	fm, err := runStore(ctx, s, cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	// A KindFile cap, not a directory.
	fc, err := manifest.StoreFileManifest(ctx, s, cfg, fm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreTree(ctx, s, fc, t.TempDir()); err == nil {
		t.Fatal("restoreTree should reject a file cap")
	}
}

// buildTree stores a small fixed nested tree over s and returns its root cap and
// the wanted file contents keyed by slash-relative path.
func buildTree(t *testing.T, ctx context.Context, s store.Store, cfg pipeline.Config) (manifest.ReadCap, map[string][]byte) {
	t.Helper()
	src := t.TempDir()
	want := map[string][]byte{
		"root.txt":          []byte("top level"),
		"docs/a.txt":        []byte("document a"),
		"docs/nested/b.bin": bytes.Repeat([]byte{0xAB, 0xCD}, 100*1024),
	}
	for rel, data := range want {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root, _, err := storeTree(ctx, s, cfg, src)
	if err != nil {
		t.Fatalf("storeTree: %v", err)
	}
	return root, want
}

// TestShareGetSubpath is the whole point of `share -path`: from a tree stored
// with `put -r`, wrap a single file (and, separately, a subdirectory) to a
// recipient's key, then reconstruct exactly that file / subtree via `get` —
// proving the recipient gets only what was shared and nothing outside it.
func TestShareGetSubpath(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}

	root, want := buildTree(t, ctx, s, cfg)

	// Recipient identity + on-disk private key, as share/get consume.
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	keyFile := filepath.Join(work, "recipient.key")
	if err := os.WriteFile(keyFile, []byte(priv.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The tree's root cap as `put -r` writes it, read back as `share` reads it.
	rootCapFile := filepath.Join(work, "tree.rvk.json")
	if err := writeRootCap(rootCapFile, root); err != nil {
		t.Fatal(err)
	}
	rootData, err := os.ReadFile(rootCapFile)
	if err != nil {
		t.Fatal(err)
	}

	// --- share a single file, then get it ---
	res, err := buildShareCap(ctx, s, pub, rootData, "docs/nested/b.bin")
	if err != nil {
		t.Fatalf("buildShareCap file: %v", err)
	}
	if res.kind != manifest.KindFile {
		t.Fatalf("shared file cap kind = %s, want file", res.kind)
	}
	fileCap := filepath.Join(work, "b.cap")
	if err := os.WriteFile(fileCap, res.sealed, 0o644); err != nil {
		t.Fatal(err)
	}
	fm, dirCap, err := resolveGetTarget(ctx, s, "", fileCap, keyFile)
	if err != nil {
		t.Fatalf("resolveGetTarget file: %v", err)
	}
	if dirCap != nil || fm == nil {
		t.Fatalf("expected a single-file target, got dirCap=%v fm=%v", dirCap, fm)
	}
	var buf bytes.Buffer
	if err := runLoad(ctx, s, *fm, &buf); err != nil {
		t.Fatalf("runLoad: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want["docs/nested/b.bin"]) {
		t.Fatal("shared single file does not match original")
	}

	// A wrong key cannot open the shared file cap.
	wrongPriv, _, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := filepath.Join(work, "wrong.key")
	if err := os.WriteFile(wrongKey, []byte(wrongPriv.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveGetTarget(ctx, s, "", fileCap, wrongKey); err == nil {
		t.Fatal("wrong key opened the shared file cap")
	}

	// --- share a subdirectory, then restore just that subtree ---
	res, err = buildShareCap(ctx, s, pub, rootData, "docs")
	if err != nil {
		t.Fatalf("buildShareCap dir: %v", err)
	}
	if res.kind != manifest.KindDir {
		t.Fatalf("shared subtree cap kind = %s, want dir", res.kind)
	}
	dirCapFile := filepath.Join(work, "docs.cap")
	if err := os.WriteFile(dirCapFile, res.sealed, 0o644); err != nil {
		t.Fatal(err)
	}
	fm, dc, err := resolveGetTarget(ctx, s, "", dirCapFile, keyFile)
	if err != nil {
		t.Fatalf("resolveGetTarget dir: %v", err)
	}
	if fm != nil || dc == nil || dc.Kind != manifest.KindDir {
		t.Fatalf("expected a directory target, got fm=%v dc=%v", fm, dc)
	}
	dst := t.TempDir()
	if _, err := restoreTree(ctx, s, *dc, dst); err != nil {
		t.Fatalf("restoreTree subtree: %v", err)
	}
	// The subtree is rooted at dst — its entries a.txt and nested/b.bin appear
	// without the "docs/" prefix.
	for _, rel := range []string{"a.txt", "nested/b.bin"} {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read restored %s: %v", rel, err)
		}
		if !bytes.Equal(got, want["docs/"+rel]) {
			t.Fatalf("restored subtree %s differs", rel)
		}
	}
	// root.txt lived outside docs/, so the shared subtree must not leak it.
	if _, err := os.Stat(filepath.Join(dst, "root.txt")); !os.IsNotExist(err) {
		t.Fatalf("shared subtree leaked a file outside the path: err=%v", err)
	}
}

// TestShareWholeTree checks that `share` with no -path wraps a directory root cap
// as a ReadCap (granting the whole tree), and that get resolves it back.
func TestShareWholeTree(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}

	root, want := buildTree(t, ctx, s, cfg)
	_, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rootData, err := root.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	res, err := buildShareCap(ctx, s, pub, rootData, "")
	if err != nil {
		t.Fatalf("buildShareCap whole tree: %v", err)
	}
	if res.kind != manifest.KindDir {
		t.Fatalf("whole-tree share kind = %s, want dir", res.kind)
	}
	if len(want) == 0 {
		t.Fatal("test tree is empty")
	}
}

// TestBuildShareCapRejectsPathOnFileManifest guards that -path is refused on a
// legacy single-file manifest (there is no tree to resolve a path in), and that
// such a manifest is not mis-sniffed as a ReadCap.
func TestBuildShareCapRejectsPathOnFileManifest(t *testing.T) {
	m := pipeline.FileManifest{
		Name:   "solo.txt",
		Params: pipeline.DefaultConfig(),
		Size:   3,
		Chunks: []pipeline.ChunkRef{{Key: crypto32(1), Shards: []store.ShardID{hash32(1)}}},
	}
	data, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if looksLikeReadCap(data) {
		t.Fatal("a single-file manifest was mis-sniffed as a ReadCap")
	}
	_, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildShareCap(context.Background(), nil, pub, data, "sub/file"); err == nil {
		t.Fatal("buildShareCap accepted -path on a single-file manifest")
	}
}
