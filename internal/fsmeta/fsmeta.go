// Package fsmeta bridges a real filesystem and revika's pipeline.Metadata: it
// captures a path's attributes into a Metadata record and restores a Metadata
// record back onto a path. It is the shared, OS-facing half of the metadata
// layer (Architecture §3.6/§3.8) — used both by revika-ctl (put/get/put -r) and
// by the OS filesystem-integration surface (internal/provider) so the two never
// diverge on how a mode, mtime, owner, symlink, or xattr round-trips.
//
// Capture is best-effort: a field a platform cannot supply (uid/gid, the
// access/change/birth times, xattrs) stays zero rather than failing the store.
// Restore is best-effort too: a single attribute that cannot be set (e.g. chown
// without privilege) is joined into the returned error but never undoes the
// others, so a retrieval still lands with whatever metadata could be applied.
//
// The portable subset (mode, mtime, content type, symlink target, hidden/
// read-only flags) is handled here; the platform-specific fields are filled by
// build-tagged helpers (fsmeta_linux.go vs fsmeta_other.go), which are no-ops on
// platforms whose stdlib cannot supply them. The native cloud-provider bindings
// (macOS File Provider, Windows Cloud Filter; Architecture §3.8) will later
// supply the richer fields on their own platforms through their framework APIs.
package fsmeta

import (
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"revika/internal/pipeline"
)

// Capture builds a pipeline.Metadata from a path already Lstat'd to fi. Portable
// fields (mode, mtime, content type, symlink target, hidden/read-only flags) are
// filled here; platform-specific fields (uid/gid, atime/ctime/btime, xattrs) are
// filled by statExtras / readXattrs, which are no-ops where the stdlib cannot
// supply them. Capture never fails: missing metadata is simply left zero.
func Capture(path string, fi fs.FileInfo) pipeline.Metadata {
	meta := pipeline.Metadata{
		Mode:      uint32(fi.Mode()),
		ModTimeNS: fi.ModTime().UnixNano(),
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if tgt, err := os.Readlink(path); err == nil {
			meta.SymlinkTarget = tgt
		}
	} else if ct := mime.TypeByExtension(filepath.Ext(path)); ct != "" {
		meta.ContentType = ct
	}
	if strings.HasPrefix(filepath.Base(path), ".") {
		meta.Flags |= pipeline.FlagHidden
	}
	if fi.Mode()&fs.ModeSymlink == 0 && fi.Mode().Perm()&0o200 == 0 {
		meta.Flags |= pipeline.FlagReadOnly
	}
	statExtras(path, fi, &meta)
	if xa := readXattrs(path); len(xa) > 0 {
		meta.Xattr = xa
	}
	return meta
}

// Restore applies meta to the file (or symlink) at path, best-effort: a failure
// to set one attribute is joined into the returned error but does not undo the
// others. Content attributes (mode/mtime) are only meaningful for regular files;
// a symlink carries its target as metadata, so for a symlink this restores only
// its ownership/xattrs via restoreExtras.
func Restore(path string, meta pipeline.Metadata) error {
	var errs []error
	if !meta.IsSymlink() {
		if meta.Mode != 0 {
			if err := os.Chmod(path, fs.FileMode(meta.Mode).Perm()); err != nil {
				errs = append(errs, fmt.Errorf("chmod: %w", err))
			}
		}
		if meta.ModTimeNS != 0 {
			mt := time.Unix(0, meta.ModTimeNS)
			at := mt
			if meta.AccessTimeNS != 0 {
				at = time.Unix(0, meta.AccessTimeNS)
			}
			if err := os.Chtimes(path, at, mt); err != nil {
				errs = append(errs, fmt.Errorf("chtimes: %w", err))
			}
		}
	}
	if err := restoreExtras(path, meta); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// RestoreSymlink recreates the symbolic link described by meta at path, replacing
// any existing entry, then restores its ownership/xattrs. It is separate from
// Restore because a symlink's "content" (its target) is metadata, not shard
// bytes, so recreating it is a metadata operation (Architecture §3.8).
func RestoreSymlink(path string, meta pipeline.Metadata) error {
	if meta.SymlinkTarget == "" {
		return fmt.Errorf("fsmeta: metadata marks a symlink but carries no target")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(meta.SymlinkTarget, path); err != nil {
		return fmt.Errorf("fsmeta: recreate symlink: %w", err)
	}
	return Restore(path, meta)
}
