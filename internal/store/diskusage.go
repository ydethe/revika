package store

import "errors"

// Usage reports the capacity of the filesystem backing a directory: the signal a
// capacity-aware placement/rebalancing policy needs so it can equalize how *full*
// nodes are (a fraction of capacity) rather than how many shards they hold — a
// Raspberry Pi and a cloud server should converge on the same fraction, not the
// same count (Architecture §3.4).
type Usage struct {
	Total uint64 // total bytes on the filesystem
	Avail uint64 // bytes available to an unprivileged process (free minus reserve)
}

// ErrUnsupported is returned by DiskUsage on platforms without a filesystem-stat
// probe. Callers treat an unsupported probe as "capacity unknown" and fall back
// to an operator-configured budget (or disable capacity balancing).
var ErrUnsupported = errors.New("store: disk usage probe unsupported on this platform")

// DiskUsage reports the total and available bytes of the filesystem that holds
// path. It is implemented per-OS (statfs on Linux) with a portable stub that
// returns ErrUnsupported elsewhere, mirroring the platform split in internal/fsmeta.
func DiskUsage(path string) (Usage, error) { return diskUsage(path) }
