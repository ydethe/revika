package fsmeta

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCaptureRestore round-trips mode and mtime through Capture → Restore
// against the real filesystem.
func TestCaptureRestore(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1_600_000_000, 0)
	if err := os.Chtimes(src, want, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	meta := Capture(src, fi)
	if got := os.FileMode(meta.Mode).Perm(); got != 0o640 {
		t.Errorf("captured mode = %o, want 640", got)
	}
	if meta.ContentType == "" {
		t.Error("expected a content type for .txt")
	}

	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(dst, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(dst, meta); err != nil {
		t.Fatalf("restore: %v", err)
	}
	rfi, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if rfi.Mode().Perm() != 0o640 {
		t.Errorf("restored mode = %o, want 640", rfi.Mode().Perm())
	}
	if rfi.ModTime().Unix() != want.Unix() {
		t.Errorf("restored mtime = %v, want %v", rfi.ModTime().Unix(), want.Unix())
	}
}

// TestRestoreSymlink recreates a symlink from metadata alone, proving a
// symlink's target round-trips as metadata rather than shard content.
func TestRestoreSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/etc/hostname", link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	meta := Capture(link, fi)
	if !meta.IsSymlink() || meta.SymlinkTarget != "/etc/hostname" {
		t.Fatalf("symlink not captured: %+v", meta)
	}

	out := filepath.Join(dir, "restored")
	if err := RestoreSymlink(out, meta); err != nil {
		t.Fatalf("RestoreSymlink: %v", err)
	}
	tgt, err := os.Readlink(out)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if tgt != "/etc/hostname" {
		t.Errorf("restored target = %q", tgt)
	}
}
