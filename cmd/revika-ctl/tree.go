package main

// tree.go adds directory support to the client: storing and retrieving a whole
// directory tree as a Merkle DAG of cap-addressed encrypted blobs
// (internal/manifest, Architecture §3.6). It is a thin driver over that package
// — capture each file's manifest as a KindFile blob, build the directory DAG
// with copy-on-write Graft, and anchor the tree with the root directory's cap —
// so the same put/get backends (single node or DHT-spread) work unchanged.
//
// The root cap plays for a tree the role the file manifest plays for a file: it
// is the read-capability written to (and read from) the -manifest path.

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"revika/internal/fsmeta"
	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// storeTree walks the directory rooted at src, stores every file as a
// cap-addressed manifest blob, and builds the directory Merkle DAG, returning
// the root directory cap and the number of files stored. Sub-directories (empty
// ones included) and per-directory metadata are preserved. WalkDir visits a
// parent before its children, so each Graft's intermediate directories already
// exist when a child is added.
func storeTree(ctx context.Context, s store.Store, cfg pipeline.Config, src string) (manifest.ReadCap, int, error) {
	rootFI, err := os.Lstat(src)
	if err != nil {
		return manifest.ReadCap{}, 0, err
	}
	if !rootFI.IsDir() {
		return manifest.ReadCap{}, 0, fmt.Errorf("%s is not a directory (drop -r to store a single file)", src)
	}

	// Start from an empty root directory carrying src's own attributes.
	root, err := manifest.StoreDir(ctx, s, cfg, manifest.NewDir(fsmeta.Capture(src, rootFI)))
	if err != nil {
		return manifest.ReadCap{}, 0, err
	}

	files := 0
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == src {
			return nil // the root itself is already stored
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}

		if d.IsDir() {
			sub, err := manifest.StoreDir(ctx, s, cfg, manifest.NewDir(fsmeta.Capture(p, fi)))
			if err != nil {
				return err
			}
			root, err = manifest.Graft(ctx, s, cfg, root, rel, sub, manifest.StatCache{Kind: manifest.KindDir, Mode: uint32(fi.Mode())})
			return err
		}

		// A regular file or a symlink: runStore captures both (a symlink's
		// content is its target path), producing a file manifest we store as a
		// KindFile blob and graft into the tree under its relative path.
		fm, err := runStore(ctx, s, cfg, p)
		if err != nil {
			return err
		}
		fc, err := manifest.StoreFileManifest(ctx, s, cfg, fm)
		if err != nil {
			return err
		}
		files++
		root, err = manifest.Graft(ctx, s, cfg, root, rel, fc, statFromManifest(fm))
		return err
	})
	if err != nil {
		return manifest.ReadCap{}, 0, err
	}
	return root, files, nil
}

// putTree stores the directory tree at src into s and writes its root cap to
// outManifest. It is the -r branch of `put`.
func putTree(ctx context.Context, s store.Store, cfg pipeline.Config, src, outManifest string) error {
	start := time.Now()
	root, files, err := storeTree(ctx, s, cfg, src)
	if err != nil {
		return fmt.Errorf("store tree %s: %w", src, err)
	}
	if err := writeRootCap(outManifest, root); err != nil {
		return fmt.Errorf("write root cap: %w", err)
	}
	fmt.Printf("Stored directory %s: %d file(s) in %s\n", src, files, time.Since(start).Round(time.Millisecond))
	fmt.Printf("Root cap: %s\n", outManifest)
	fmt.Fprintln(os.Stderr, "warning: the root cap unlocks every file in the tree — keep it secret, or `share` it wrapped to a recipient.")
	return nil
}

// getTree restores the tree rooted at root into dest. It is the -r branch of `get`.
func getTree(ctx context.Context, s store.Store, root manifest.ReadCap, dest string) error {
	files, err := restoreTree(ctx, s, root, dest)
	if err != nil {
		return fmt.Errorf("restore tree: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Restored %d file(s) into %s\n", files, dest)
	return nil
}

// statFromManifest builds the StatCache a directory keeps for a file child, so a
// reader can serve readdir/getattr without hydrating the file (§3.8).
func statFromManifest(fm pipeline.FileManifest) manifest.StatCache {
	return manifest.StatCache{
		Kind:           manifest.KindFile,
		Size:           fm.Size,
		Mode:           fm.Meta.Mode,
		ModTimeNS:      fm.Meta.ModTimeNS,
		ContentVersion: fm.Meta.ContentVersion,
		MetaVersion:    fm.Meta.MetaVersion,
	}
}

// restoreTree materializes the directory tree rooted at root into dest,
// recreating files, symlinks, sub-directories, and their metadata. It returns
// the number of files written.
func restoreTree(ctx context.Context, s store.Store, root manifest.ReadCap, dest string) (int, error) {
	if root.Kind != manifest.KindDir {
		return 0, fmt.Errorf("root cap is a %s, not a directory (drop -r to get a single file)", root.Kind)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, err
	}
	return restoreDir(ctx, s, root, dest)
}

func restoreDir(ctx context.Context, s store.Store, dirCap manifest.ReadCap, dest string) (int, error) {
	d, err := manifest.LoadDir(ctx, s, dirCap)
	if err != nil {
		return 0, err
	}
	files := 0
	for _, e := range d.Entries {
		if err := safeEntryName(e.Name); err != nil {
			return files, err
		}
		target := filepath.Join(dest, e.Name)
		switch e.Cap.Kind {
		case manifest.KindDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return files, err
			}
			n, err := restoreDir(ctx, s, e.Cap, target)
			files += n
			if err != nil {
				return files, err
			}
		case manifest.KindFile:
			n, err := restoreFile(ctx, s, e.Cap, target)
			files += n
			if err != nil {
				return files, err
			}
		default:
			return files, fmt.Errorf("entry %q has unknown cap kind %s", e.Name, e.Cap.Kind)
		}
	}
	// Restore the directory's own metadata after its children are in place.
	if err := fsmeta.Restore(dest, d.Meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial metadata restore for %s: %v\n", dest, err)
	}
	return files, nil
}

// restoreFile writes the single file addressed by fc to target, reusing the same
// content + symlink + metadata restore path as `get` on a lone file.
func restoreFile(ctx context.Context, s store.Store, fc manifest.ReadCap, target string) (int, error) {
	fm, err := manifest.LoadFileManifest(ctx, s, fc)
	if err != nil {
		return 0, err
	}
	if fm.Meta.IsSymlink() {
		if err := fsmeta.RestoreSymlink(target, fm.Meta); err != nil {
			return 0, err
		}
		return 1, nil
	}
	f, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	if err := runLoad(ctx, s, fm, f); err != nil {
		f.Close()
		return 0, fmt.Errorf("retrieve %s: %w", target, err)
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := fsmeta.Restore(target, fm.Meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial metadata restore for %s: %v\n", target, err)
	}
	return 1, nil
}

// writeRootCap serializes a tree's root cap (the read-capability) to path.
func writeRootCap(path string, c manifest.ReadCap) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
