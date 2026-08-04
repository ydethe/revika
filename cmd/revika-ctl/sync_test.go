package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"revika/internal/pipeline"
)

// TestSyncThenHydrate covers the lazy-materialization loop: `sync` recreates the
// namespace with empty placeholders (fetching no file content), then `hydrate`
// fills chosen files from the recorded caps.
func TestSyncThenHydrate(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}

	root, want := buildTree(t, ctx, s, cfg)

	dest := t.TempDir()
	if err := syncTree(ctx, s, root, dest); err != nil {
		t.Fatalf("syncTree: %v", err)
	}

	// The namespace exists: every directory and a 0-byte placeholder per file.
	for rel := range want {
		p := filepath.Join(dest, filepath.FromSlash(rel))
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("placeholder %s missing: %v", rel, err)
		}
		if fi.Size() != 0 {
			t.Fatalf("placeholder %s is %d bytes, want 0 (content should not be synced)", rel, fi.Size())
		}
	}

	// The index was written and lists every file, all un-hydrated.
	idx, err := readSyncIndex(dest)
	if err != nil {
		t.Fatalf("readSyncIndex: %v", err)
	}
	if len(idx.Files) != len(want) {
		t.Fatalf("index has %d files, want %d", len(idx.Files), len(want))
	}
	for _, f := range idx.Files {
		if f.Hydrated {
			t.Fatalf("file %s marked hydrated right after sync", f.Path)
		}
	}

	// Hydrate a single file: only it gains content; the rest stay placeholders.
	plan, err := planHydrate("", []string{filepath.Join(dest, "docs", "a.txt")})
	if err != nil {
		t.Fatalf("planHydrate one file: %v", err)
	}
	if n, err := runHydrateGroup(ctx, s, plan[0]); err != nil || n != 1 {
		t.Fatalf("hydrate one file: n=%d err=%v (want 1, nil)", n, err)
	}
	assertFileBytes(t, dest, "docs/a.txt", want["docs/a.txt"])
	assertPlaceholder(t, dest, "docs/nested/b.bin")
	assertPlaceholder(t, dest, "root.txt")

	// Hydrate the whole tree via -C with no paths; every file now matches.
	plan, err = planHydrate(dest, nil)
	if err != nil {
		t.Fatalf("planHydrate all: %v", err)
	}
	if _, err := runHydrateGroup(ctx, s, plan[0]); err != nil {
		t.Fatalf("hydrate all: %v", err)
	}
	for rel, data := range want {
		assertFileBytes(t, dest, rel, data)
	}

	// The persisted index reflects the hydration.
	idx, err = readSyncIndex(dest)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range idx.Files {
		if !f.Hydrated {
			t.Fatalf("file %s still un-hydrated after hydrating all", f.Path)
		}
	}
}

// TestHydrateSubtree hydrates a directory prefix and asserts only files beneath
// it are filled.
func TestHydrateSubtree(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}

	root, want := buildTree(t, ctx, s, cfg)
	dest := t.TempDir()
	if err := syncTree(ctx, s, root, dest); err != nil {
		t.Fatalf("syncTree: %v", err)
	}

	// "docs" covers docs/a.txt and docs/nested/b.bin, but not root.txt.
	plan, err := planHydrate("", []string{filepath.Join(dest, "docs")})
	if err != nil {
		t.Fatalf("planHydrate subtree: %v", err)
	}
	n, err := runHydrateGroup(ctx, s, plan[0])
	if err != nil {
		t.Fatalf("hydrate subtree: %v", err)
	}
	if n != 2 {
		t.Fatalf("hydrated %d files under docs/, want 2", n)
	}
	assertFileBytes(t, dest, "docs/a.txt", want["docs/a.txt"])
	assertFileBytes(t, dest, "docs/nested/b.bin", want["docs/nested/b.bin"])
	assertPlaceholder(t, dest, "root.txt")
}

func assertFileBytes(t *testing.T, dest, rel string, data []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("%s = %d bytes, want %d", rel, len(got), len(data))
	}
}

func assertPlaceholder(t *testing.T, dest, rel string) {
	t.Helper()
	fi, err := os.Stat(filepath.Join(dest, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("stat %s: %v", rel, err)
	}
	if fi.Size() != 0 {
		t.Fatalf("%s = %d bytes, want a 0-byte placeholder", rel, fi.Size())
	}
}
