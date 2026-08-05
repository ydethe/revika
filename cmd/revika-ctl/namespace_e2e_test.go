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

	// --- sharing: seal the docs/ subtree to a recipient, who reads it ---
	recipientSign, recipientPriv, recipientPub := genIdentity(t, home, "recipient")
	sharedFile := filepath.Join(t.TempDir(), "docs.root.json")
	capture(t, func() error {
		return cmdShare([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign,
			"-to", "@" + recipientPub, "-o", sharedFile, "rvk:docs"})
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

	// --- rm: remove the file, then confirm docs/ is empty ---
	capture(t, func() error {
		return cmdRm([]string{"-node", addr, "-root", rootFile, "-signkey", ownerSign, "rvk:docs/report.pdf"})
	})
	if out := capture(t, func() error {
		return cmdLs([]string{"-node", addr, "-root", rootFile, "rvk:docs"})
	}); strings.Contains(out, "report.pdf") {
		t.Fatalf("after rm, ls rvk:docs still lists report.pdf: %q", out)
	}
}
