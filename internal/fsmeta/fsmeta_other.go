//go:build !linux

package fsmeta

import (
	"io/fs"

	"revika/internal/pipeline"
)

// On non-Linux platforms the stdlib does not portably expose uid/gid, the
// access/change/birth times, or extended attributes, so these are no-ops: a
// captured Metadata still carries the portable subset (mode, mtime, content
// type, symlink target, flags) and the full schema, but the richer fields stay
// zero until the native cloud-provider bindings land (macOS File Provider /
// Windows Cloud Filter; Architecture §3.8), which supply them through their own
// platform APIs.
func statExtras(path string, fi fs.FileInfo, meta *pipeline.Metadata) {}

func readXattrs(path string) map[string][]byte { return nil }

func restoreExtras(path string, meta pipeline.Metadata) error { return nil }
