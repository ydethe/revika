//go:build !linux

package store

// diskUsage has no portable implementation; callers treat ErrUnsupported as
// "capacity unknown". A native probe (statfs on darwin, GetDiskFreeSpaceEx on
// windows) can be added under its own build tag when those nodes are targeted.
func diskUsage(string) (Usage, error) { return Usage{}, ErrUnsupported }
