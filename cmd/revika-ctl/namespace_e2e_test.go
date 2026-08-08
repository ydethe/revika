package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// capture redirects os.Stdout while fn runs and returns everything it printed.
// It fails the test if fn returns an error (surfacing the captured output for
// context), so callers read a command's stdout as plainly as a shell would.
func capture(t *testing.T, fn func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	ferr := fn()
	w.Close()
	os.Stdout = old
	out := <-done
	if ferr != nil {
		t.Fatalf("command error: %v (output: %s)", ferr, out)
	}
	return out
}

// genIdentity mints a User identity (pow disabled for speed) under a fresh prefix
// and returns the paths cp/ls/rm/share consume.
func genIdentity(t *testing.T, dir, name string) (signKey, encPriv, encPub string) {
	t.Helper()
	prefix := filepath.Join(dir, name)
	if err := cmdKeygen([]string{"-key", prefix, "-pow-difficulty", "0"}); err != nil {
		t.Fatalf("keygen %s: %v", name, err)
	}
	return prefix + ".sign.key", prefix + ".key", prefix + ".pub"
}

// TestNamespaceE2E drives the whole namespace CLI surface over a real in-process
// storage node: cp (store) → ls → cp (retrieve) → share → recipient ls/cp → rm →
// ls, plus the read-only guards on a shared root.
func TestNamespaceE2E(t *testing.T) {
	ctx := t.Context()
	addr, _ := startStorageNode(t, ctx, "")

	home := t.TempDir()
	ownerSign, _, _ := genIdentity(t, home, "owner")
	rootFile := filepath.Join(home, "root.json")

	// A multi-chunk-ish payload to store.
	payload := bytes.Repeat([]byte("revika-namespace-"), 6000)
	srcFile := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(srcFile, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	// cp report.pdf rvk:docs/  (a trailing slash: into docs/ under the base name)
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, srcFile, "rvk:docs/"})
	})

	// ls rvk:  lists the root — docs/ appears as a directory.
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile})
	}); !strings.Contains(out, "docs/") {
		t.Fatalf("ls rvk: = %q, want docs/", out)
	}

	// ls rvk:docs  lists the file; -l shows the file kind and its byte size.
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:docs"})
	}); !strings.Contains(out, "report.pdf") {
		t.Fatalf("ls rvk:docs = %q, want report.pdf", out)
	}
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "-l", "rvk:docs"})
	}); !strings.Contains(out, "report.pdf") || !strings.Contains(out, strconv.Itoa(len(payload))) {
		t.Fatalf("ls -l rvk:docs = %q, want report.pdf and size %d", out, len(payload))
	}

	// cp rvk:docs/report.pdf <dir>  retrieves into the directory under its name.
	dstDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "rvk:docs/report.pdf", dstDir})
	})
	if got, err := os.ReadFile(filepath.Join(dstDir, "report.pdf")); err != nil {
		t.Fatalf("read retrieved file: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatalf("retrieved %d bytes, want %d", len(got), len(payload))
	}

	// --- rvk:→rvk: copy within the namespace (copy-on-write, no re-encryption) ---
	// Copy the file to a new path and to a sibling name, then confirm both read back.
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/report.pdf", "rvk:backup/report.pdf"})
	})
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/report.pdf", "rvk:docs/copy.pdf"})
	})
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:backup"})
	}); !strings.Contains(out, "report.pdf") {
		t.Fatalf("after rvk:→rvk: copy, ls rvk:backup = %q, want report.pdf", out)
	}
	copyDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "rvk:backup/report.pdf", copyDir})
	})
	if got, err := os.ReadFile(filepath.Join(copyDir, "report.pdf")); err != nil {
		t.Fatalf("read rvk:→rvk: copy: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatal("rvk:→rvk: copied file does not match original")
	}

	// Removing one copy must not delete shards the other copy still shares (by
	// content address): rvk:docs/copy.pdf and rvk:backup/report.pdf point at the
	// same cap. After rm of the docs copy, the backup copy must still read back.
	capture(t, func() error {
		return cmdRm([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/copy.pdf"})
	})
	afterRmDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "rvk:backup/report.pdf", afterRmDir})
	})
	if got, err := os.ReadFile(filepath.Join(afterRmDir, "report.pdf")); err != nil {
		t.Fatalf("backup copy unreadable after rm of a shared-shard sibling: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatal("backup copy corrupted after rm of a shared-shard sibling")
	}

	// --- sharing: seal the docs/ subtree to a recipient, who reads it ---
	recipientSign, recipientPriv, recipientPub := genIdentity(t, home, "recipient")
	sharedFile := filepath.Join(t.TempDir(), "docs.root.json")
	capture(t, func() error {
		return cmdShare([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign,
			"-to", recipientPub, "-o", sharedFile, "rvk:docs"})
	})

	// The recipient's -root is the sealed file, opened with their private key. The
	// shared root is anchored at docs/, so report.pdf sits at its top level.
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", sharedFile, "-key", recipientPriv})
	}); !strings.Contains(out, "report.pdf") {
		t.Fatalf("recipient ls shared root = %q, want report.pdf", out)
	}
	recvDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", sharedFile, "-key", recipientPriv, "rvk:report.pdf", recvDir})
	})
	if got, err := os.ReadFile(filepath.Join(recvDir, "report.pdf")); err != nil {
		t.Fatalf("recipient read: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatal("recipient retrieved file does not match original")
	}

	// A wrong key cannot open the sealed shared root.
	_, wrongPriv, _ := genIdentity(t, home, "stranger")
	if err := cmdLs([]string{"-node", addr, "-root", sharedFile, "-key", wrongPriv}); err == nil {
		t.Fatal("ls opened a sealed shared root with the wrong key")
	}

	// The shared root is read-only: storing into it (even with the recipient's own
	// signing key) is refused.
	if err := cmdCp([]string{"-node", addr, "-root", sharedFile, "-key", recipientPriv,
		"-signkey", recipientSign, srcFile, "rvk:evil.txt"}); err == nil {
		t.Fatal("cp stored into a shared read-only root")
	}

	// --- rm: remove the ORIGINAL, then confirm docs/ is empty ---
	// rvk:backup/report.pdf is a copy of this file and shares its shards by content
	// address, so removing the original must leave the copy fully readable — the
	// two paths behave as independent files (rm one never affects the other).
	capture(t, func() error {
		return cmdRm([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/report.pdf"})
	})
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:docs"})
	}); strings.Contains(out, "report.pdf") {
		t.Fatalf("after rm, ls rvk:docs still lists report.pdf: %q", out)
	}

	// The independent copy survives removal of the original, byte-for-byte.
	survivorDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "rvk:backup/report.pdf", survivorDir})
	})
	if got, err := os.ReadFile(filepath.Join(survivorDir, "report.pdf")); err != nil {
		t.Fatalf("copy unreadable after rm of the original: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatal("copy corrupted after rm of the original — copies are not independent")
	}
}

// TestNamespaceMv drives rvk:→rvk: rename/move: a file rename within a directory,
// a move into another directory, guards against moving onto itself or into its
// own subtree, and confirms the moved bytes read back unchanged while the source
// path disappears.
func TestNamespaceMv(t *testing.T) {
	ctx := t.Context()
	addr, _ := startStorageNode(t, ctx, "")

	home := t.TempDir()
	ownerSign, _, _ := genIdentity(t, home, "owner")
	rootFile := filepath.Join(home, "root.json")

	payload := bytes.Repeat([]byte("revika-mv-"), 5000)
	srcFile := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(srcFile, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	// Seed the namespace: docs/report.pdf.
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, srcFile, "rvk:docs/"})
	})

	// Rename within docs/: report.pdf -> final.pdf. The old name vanishes, the new
	// one holds the original bytes.
	capture(t, func() error {
		return cmdMv([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/report.pdf", "rvk:docs/final.pdf"})
	})
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:docs"})
	}); strings.Contains(out, "report.pdf") || !strings.Contains(out, "final.pdf") {
		t.Fatalf("after mv, ls rvk:docs = %q, want final.pdf and no report.pdf", out)
	}
	renamedDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "rvk:docs/final.pdf", renamedDir})
	})
	if got, err := os.ReadFile(filepath.Join(renamedDir, "final.pdf")); err != nil {
		t.Fatalf("read renamed file: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatal("renamed file does not match original")
	}

	// Move into another directory via a trailing slash: docs/final.pdf -> archive/final.pdf.
	capture(t, func() error {
		return cmdMv([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/final.pdf", "rvk:archive/"})
	})
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:archive"})
	}); !strings.Contains(out, "final.pdf") {
		t.Fatalf("after mv into archive/, ls rvk:archive = %q, want final.pdf", out)
	}
	movedDir := t.TempDir()
	capture(t, func() error {
		return cmdCp([]string{"-node", addr, "-root", rootFile, "rvk:archive/final.pdf", movedDir})
	})
	if got, err := os.ReadFile(filepath.Join(movedDir, "final.pdf")); err != nil {
		t.Fatalf("read moved file: %v", err)
	} else if !bytes.Equal(got, payload) {
		t.Fatal("moved file does not match original")
	}

	// Moving a directory onto the same path is rejected (no-op guard).
	if err := cmdMv([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:archive", "rvk:archive"}); err == nil {
		t.Fatal("mv allowed source == destination")
	}
	// Moving a directory into its own subtree is rejected (would drop the data).
	if err := cmdMv([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:archive", "rvk:archive/nested"}); err == nil {
		t.Fatal("mv allowed moving a directory into its own subtree")
	}
	// The archive/ subtree survived the rejected moves intact.
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:archive"})
	}); !strings.Contains(out, "final.pdf") {
		t.Fatalf("after rejected moves, ls rvk:archive = %q, want final.pdf still present", out)
	}

	// mv needs two rvk: paths — a local endpoint is rejected (that is cp's job).
	if err := cmdMv([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:archive/final.pdf", srcFile}); err == nil {
		t.Fatal("mv accepted a local destination")
	}
}
