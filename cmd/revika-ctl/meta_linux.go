//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"revika/internal/pipeline"
)

// statExtras fills the POSIX fields the portable os.FileInfo does not expose:
// owner/group and the access/change times, read from the underlying stat_t.
// Birth time is not surfaced by the stdlib syscall package on Linux (it needs
// statx), so BirthTimeNS is left zero here and populated only where a platform
// can supply it.
func statExtras(path string, fi fs.FileInfo, meta *pipeline.Metadata) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	meta.Uid = st.Uid
	meta.Gid = st.Gid
	meta.AccessTimeNS = st.Atim.Nano()
	meta.ChangeTimeNS = st.Ctim.Nano()
}

// readXattrs reads all extended attributes of path (following the semantics of
// the plain listxattr/getxattr syscalls). It returns nil on any error or when
// the file has none — xattr capture is best-effort and never blocks a store.
func readXattrs(path string) map[string][]byte {
	size, err := syscall.Listxattr(path, nil)
	if err != nil || size == 0 {
		return nil
	}
	buf := make([]byte, size)
	size, err = syscall.Listxattr(path, buf)
	if err != nil {
		return nil
	}
	out := make(map[string][]byte)
	for _, name := range splitNull(buf[:size]) {
		vsize, err := syscall.Getxattr(path, name, nil)
		if err != nil || vsize == 0 {
			continue
		}
		val := make([]byte, vsize)
		vsize, err = syscall.Getxattr(path, name, val)
		if err != nil {
			continue
		}
		out[name] = val[:vsize]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// restoreExtras restores ownership and extended attributes. Lchown is used so a
// symlink's own ownership is set rather than its target's; both are best-effort
// (chown typically needs privilege), and every failure is joined so the caller
// can warn without failing the retrieval.
func restoreExtras(path string, meta pipeline.Metadata) error {
	var errs []error
	if meta.Uid != 0 || meta.Gid != 0 {
		if err := os.Lchown(path, int(meta.Uid), int(meta.Gid)); err != nil {
			errs = append(errs, fmt.Errorf("lchown: %w", err))
		}
	}
	for name, val := range meta.Xattr {
		if err := syscall.Setxattr(path, name, val, 0); err != nil {
			errs = append(errs, fmt.Errorf("setxattr %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// splitNull splits a NUL-separated, NUL-terminated blob (the listxattr layout)
// into its constituent names, dropping empties.
func splitNull(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}
