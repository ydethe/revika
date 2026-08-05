//go:build linux

package store

import (
	"fmt"
	"syscall"
)

// diskUsage probes the filesystem holding path with statfs(2). Total and
// available bytes are the block counts scaled by the fundamental block size;
// Bavail (blocks free to an unprivileged process) is used rather than Bfree so
// the figure matches what the node can actually write.
func diskUsage(path string) (Usage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Usage{}, fmt.Errorf("store: statfs %s: %w", path, err)
	}
	bs := uint64(st.Bsize)
	return Usage{Total: st.Blocks * bs, Avail: st.Bavail * bs}, nil
}
