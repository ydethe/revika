# fsmeta

The bridge between an on-disk file and revika's cross-platform metadata record.
It captures a local file's POSIX/OS attributes into a `pipeline.Metadata` on
store, and restores them onto a recreated file on retrieval — the metadata half
of the store/retrieve loop ([Architecture §3.6](../../Architecture.md)).

## Why it exists

`pipeline.Metadata` is the *serialized, platform-neutral* attribute record (mode,
owner, the four times, flags, content-type, symlink target, xattrs, and the
version tokens). Turning a live `os.FileInfo` + path into that record — and back —
needs `syscall` and is inherently platform-specific. Isolating it here keeps that
OS-specific code in one place and lets every caller (`revika-ctl`, and the
`internal/provider` mount surface) share one implementation instead of
re-deriving it.

## Exported functions

```go
// Capture reads path's attributes (fi is its already-obtained FileInfo) into a
// platform-neutral Metadata, including a symlink's target.
func Capture(path string, fi fs.FileInfo) pipeline.Metadata

// Restore applies a Metadata back onto an existing regular file or directory at
// path (mode, times, owner where permitted, xattrs).
func Restore(path string, meta pipeline.Metadata) error

// RestoreSymlink recreates a symlink at path pointing at meta.SymlinkTarget.
func RestoreSymlink(path string, meta pipeline.Metadata) error
```

## Platform split

The portable surface lives in `fsmeta.go`; the OS-specific extras sit behind
build-tagged helpers:

- `fsmeta_linux.go` (`//go:build linux`) — uid/gid, atime/ctime via
  `syscall.Stat_t`, and xattr read/restore.
- `fsmeta_other.go` (`//go:build !linux`) — no-op stubs, so the package builds and
  the core mode/mtime round-trip works everywhere.

Symlink targets and the four timestamps that `os` exposes portably round-trip on
every platform; owner and xattrs are best-effort and Linux-only for now.
