package main

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

// captureMetadata builds a pipeline.Metadata from a path already Lstat'd to fi.
// Portable fields (mode, mtime, content type, symlink target, hidden/read-only
// flags) are filled here; platform-specific fields (uid/gid, atime/ctime/btime,
// xattrs) are filled by statExtras / readXattrs, which are no-ops on platforms
// whose stdlib cannot supply them (see meta_linux.go vs meta_other.go). Capture
// is best-effort: missing metadata never blocks a store.
func captureMetadata(path string, fi fs.FileInfo) pipeline.Metadata {
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

// restoreMetadata applies meta to the file (or symlink) at path, best-effort: a
// failure to set one attribute (e.g. chown without privilege) is joined into the
// returned error but does not undo the others, so a retrieval still succeeds with
// whatever metadata could be restored. Content (mode/mtime) is only meaningful
// for regular files; symlinks carry their target as metadata, so this restores
// only their ownership/xattrs via restoreExtras.
func restoreMetadata(path string, meta pipeline.Metadata) error {
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
