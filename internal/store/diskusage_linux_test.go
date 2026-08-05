//go:build linux

package store

import "testing"

// TestDiskUsageLinux checks the statfs probe returns sane, non-zero figures for
// a real directory and that available never exceeds total.
func TestDiskUsageLinux(t *testing.T) {
	u, err := DiskUsage(t.TempDir())
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}
	if u.Total == 0 {
		t.Fatalf("Total = 0, want a non-zero filesystem capacity")
	}
	if u.Avail > u.Total {
		t.Fatalf("Avail %d exceeds Total %d", u.Avail, u.Total)
	}
}

// TestDiskUsageMissing surfaces an error for a path that does not exist.
func TestDiskUsageMissing(t *testing.T) {
	if _, err := DiskUsage("/no/such/path/revika-test"); err == nil {
		t.Fatal("DiskUsage of a missing path returned nil error")
	}
}
