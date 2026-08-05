// Package sync is revika's folder-watch + reconcile engine: it keeps a local
// directory and a User's stored namespace (the cap-addressed Merkle DAG behind a
// provider.Provider) in agreement, both ways (Architecture §3.7/§3.8; the
// "daemon folder-watch + reconcile" of CLAUDE.md's repo layout).
//
// Where internal/provider is the on-demand, per-callback filesystem surface a
// native OS extension drives, this package is the standalone, headless
// alternative: a background loop that periodically scans a real directory,
// diffs it against the stored tree, and applies the deltas in both directions —
// the model a `revika-daemon` runs to make an ordinary folder a synced folder,
// without any OS integration.
//
// # How it decides (three-way reconcile)
//
// Two-way sync cannot tell "I changed this" from "they deleted it"; a *three-way*
// reconcile can. The engine keeps a persisted base state — the last point at
// which the two sides agreed — and compares the current local scan and remote
// scan against it. For each path it learns whether each side is new, changed,
// unchanged, or deleted *since the agreement*, and turns that into an
// unambiguous action:
//
//	local new / changed, remote unchanged   → upload   (create/modify remote)
//	remote new / changed, local unchanged   → download (create/modify local)
//	local deleted, remote unchanged         → delete remote
//	remote deleted, local unchanged         → delete local
//	both changed (or both new, no base)     → conflict → resolved by ConflictPolicy
//
// Because the stored tree is a Merkle DAG of content-addressed blobs, the remote
// side exposes cheap content/metadata version tokens (provider.ItemVersion), so
// "changed remotely" is a token comparison, never a re-download.
//
// # Watching without a kernel hook
//
// The PoC watches by *polling* (Daemon), not by a kernel notification API: it
// re-scans on a fixed cadence. This keeps the package pure-Go and dependency-free
// (CLAUDE.md), portable across every OS, and trivially testable (a test just
// calls Reconcile). Wiring an event source (inotify/FSEvents/ReadDirectoryChanges
// or the native provider callbacks) to trigger a reconcile sooner is a drop-in
// refinement — the reconcile logic is identical either way.
//
// # What it is not (yet)
//
// The engine reconciles files, symlinks, and directories (add/modify/delete in
// both directions) and detects conflicts. It does not yet do content-hash-based
// change detection (it uses size+mtime, the classic rsync heuristic), rename
// detection (a move surfaces as delete+add), or partial-file transfer; these are
// noted in the README as follow-ups.
//
// Defence controls (security/Defence.md): the engine drives everything through
// provider.Provider, so every byte it uploads is chunked, encrypted, and
// erasure-coded client-side (SC-28/SC-36 inherited from the pipeline) before any
// shard leaves the machine; it never weakens that path.
package sync

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"revika/internal/provider"
)

// kind classifies a filesystem object for reconcile: a directory, or a leaf
// (regular file or symlink). Leaf-vs-leaf differences (a file becoming a symlink)
// are handled as a content change; a directory-vs-leaf swap at one path is a kind
// mismatch, treated conservatively as a conflict.
type kind uint8

const (
	kindLeaf kind = iota // regular file or symlink
	kindDir
)

// localState is one entry of a local directory scan: enough to detect a change
// (size + mtime, the rsync heuristic) and to classify the object, without
// reading its content.
type localState struct {
	kind      kind
	isSymlink bool
	size      int64
	mtimeNS   int64
	mode      uint32
}

// localSnapshot maps a slash-relative path (from the sync root) to its state.
type localSnapshot map[string]localState

// scanLocal walks root and returns the state of every entry beneath it, keyed by
// slash-relative path. The root itself is not included. Entries for which
// ignore reports true (e.g. the state sidecar) are skipped, and a directory that
// is ignored is not descended into. A path that cannot be Lstat'd is skipped
// rather than failing the whole scan (best-effort, like fsmeta.Capture).
func scanLocal(root string, ignore func(rel string) bool) (localSnapshot, error) {
	snap := localSnapshot{}
	err := filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory should not abort the whole scan; skip it.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if abs == root {
			return nil
		}
		rel, rerr := relSlash(root, abs)
		if rerr != nil {
			return nil
		}
		if ignore != nil && ignore(rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		fi, ierr := d.Info() // Lstat semantics from WalkDir: symlinks are not followed
		if ierr != nil {
			return nil
		}
		st := localState{
			size:    fi.Size(),
			mtimeNS: fi.ModTime().UnixNano(),
			mode:    uint32(fi.Mode()),
		}
		switch {
		case fi.IsDir():
			st.kind = kindDir
		case fi.Mode()&fs.ModeSymlink != 0:
			st.kind = kindLeaf
			st.isSymlink = true
		default:
			st.kind = kindLeaf
		}
		snap[rel] = st
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sync: scan %q: %w", root, err)
	}
	return snap, nil
}

// relSlash returns abs relative to root as a slash-separated path.
func relSlash(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// localAbs maps a slash-relative path back to an absolute filesystem path under
// root.
func localAbs(root, rel string) string {
	return filepath.Join(root, filepath.FromSlash(rel))
}

// parentPath returns the slash-parent of a path ("" for a top-level entry).
func parentPath(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}

// baseName returns the final component of a slash path.
func baseName(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return p
	}
	return p[i+1:]
}

// depth counts the path components (used to order operations parents-first /
// children-first).
func depth(p string) int {
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// pathExists reports whether an entry (of any kind) exists at abs, following no
// symlink (a dangling symlink still "exists").
func pathExists(abs string) bool {
	_, err := os.Lstat(abs)
	return err == nil
}

// itemKindOf classifies a provider.Item.
func itemKindOf(it provider.Item) kind {
	if it.IsDir {
		return kindDir
	}
	return kindLeaf
}
