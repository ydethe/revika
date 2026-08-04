package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"revika/internal/manifest"
	"revika/internal/pipeline"
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
