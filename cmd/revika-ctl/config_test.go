package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConnectWritesConfig checks `connect` creates the workspace folder and a
// config.json that resolveWorkspace reads back with the settings intact.
func TestConnectWritesConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	args := []string{
		"-root", dir,
		"-label", "home nas",
		"-k", "6", "-m", "3",
		"-pow-difficulty", "8", "-pow-puzzle", "sha256",
		"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWtest",
	}
	if err := cmdConnect(args); err != nil {
		t.Fatalf("connect: %v", err)
	}

	ws, err := resolveWorkspace(dir)
	if err != nil {
		t.Fatalf("resolveWorkspace: %v", err)
	}
	if ws.fileMode {
		t.Fatal("workspace dir resolved as file mode")
	}
	if ws.RootFile != filepath.Join(dir, rootFileName) {
		t.Fatalf("root file = %q", ws.RootFile)
	}
	if ws.Config == nil {
		t.Fatal("config.json not loaded")
	}
	if ws.Config.Label != "home nas" {
		t.Fatalf("label = %q", ws.Config.Label)
	}
	if got := ws.Config.Bootstrap; len(got) != 1 || got[0] != "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWtest" {
		t.Fatalf("bootstrap = %v", got)
	}
	if ws.Config.Erasure.K != 6 || ws.Config.Erasure.M != 3 {
		t.Fatalf("erasure = %+v", ws.Config.Erasure)
	}
	if ws.Config.PoW.Difficulty != 8 || ws.Config.PoW.Puzzle != "sha256" {
		t.Fatalf("pow = %+v", ws.Config.PoW)
	}

	// The erasure params flow through to the pipeline config.
	if p := ws.pipelineConfig().Params; p.K != 6 || p.M != 3 {
		t.Fatalf("pipelineConfig params = %+v", p)
	}
	// Keys default under the workspace, not the historical .revika.
	if want := filepath.Join(dir, "keys", "user.sign.key"); ws.signKeyPath("") != want {
		t.Fatalf("signKeyPath = %q, want %q", ws.signKeyPath(""), want)
	}
	if ws.signKeyPath("/explicit/x.sign.key") != "/explicit/x.sign.key" {
		t.Fatal("explicit -signkey flag not honoured")
	}
}

// TestConnectRefusesOverwrite checks connect will not clobber an existing
// config.json unless -force is given.
func TestConnectRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	base := []string{"-root", dir, "-bootstrap", "/ip4/1.2.3.4/tcp/1/p2p/12D3KooWa"}
	if err := cmdConnect(base); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if err := cmdConnect(base); err == nil {
		t.Fatal("second connect overwrote config without -force")
	}
	if err := cmdConnect(append(base, "-force")); err != nil {
		t.Fatalf("connect -force: %v", err)
	}
}

// TestConnectRejectsBadArgs covers the validation guards.
func TestConnectRejectsBadArgs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	cases := [][]string{
		{"-root", dir}, // no bootstrap
		{"-root", dir, "-k", "0", "/ip4/1/tcp/1/p2p/x"},             // k < 1
		{"-root", dir, "-pow-puzzle", "nope", "/ip4/1/tcp/1/p2p/x"}, // bad puzzle
	}
	for i, args := range cases {
		if err := cmdConnect(args); err == nil {
			t.Fatalf("case %d: expected error, got nil", i)
		}
	}
}

// TestResolveWorkspaceFileMode checks a -root that names a regular file is a
// bare root pointer with no workspace config, keys falling back to .revika.
func TestResolveWorkspaceFileMode(t *testing.T) {
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "share.root.json")
	if err := os.WriteFile(rootFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err := resolveWorkspace(rootFile)
	if err != nil {
		t.Fatalf("resolveWorkspace: %v", err)
	}
	if !ws.fileMode {
		t.Fatal("regular file not resolved as file mode")
	}
	if ws.RootFile != rootFile {
		t.Fatalf("root file = %q", ws.RootFile)
	}
	if ws.Config != nil {
		t.Fatal("file mode should carry no config")
	}
	if want := filepath.Join(defaultWorkspaceDir, "keys", "user.sign.key"); ws.signKeyPath("") != want {
		t.Fatalf("signKeyPath = %q, want %q", ws.signKeyPath(""), want)
	}
}

// TestBackendMerge checks explicit selectors override config bootstrap while an
// empty selector set falls back to it.
func TestBackendMerge(t *testing.T) {
	ws := &Workspace{Config: &Config{Bootstrap: []string{"/cfg/a", "/cfg/b"}}}

	// No explicit selector: config bootstrap stands in.
	node, boots, mdns := ws.backend("", nil, false)
	if node != "" || mdns || len(boots) != 2 || boots[0] != "/cfg/a" {
		t.Fatalf("fallback merge = %q %v %v", node, boots, mdns)
	}
	// Explicit -node wins, config ignored.
	if n, b, _ := ws.backend("/node/x", nil, false); n != "/node/x" || len(b) != 0 {
		t.Fatalf("explicit node not honoured: %q %v", n, b)
	}
	// Explicit -bootstrap wins.
	if _, b, _ := ws.backend("", []string{"/flag/z"}, false); len(b) != 1 || b[0] != "/flag/z" {
		t.Fatalf("explicit bootstrap not honoured: %v", b)
	}

	// A workspace with no config leaves the selectors untouched.
	empty := &Workspace{}
	if n, b, m := empty.backend("", nil, false); n != "" || len(b) != 0 || m {
		t.Fatalf("empty workspace altered selectors: %q %v %v", n, b, m)
	}
}
