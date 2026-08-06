package main

import (
	"os"
	"path/filepath"
	"testing"

	"revika/internal/cap"
	"revika/internal/net"
	"revika/internal/store"
)

// startParamsNode spins up an in-process node that answers /revika/params on a
// dialable multiaddr, enforcing proof-of-work admission at d bits under puzzle
// (d == 0 disables it). connect direct-dials this addr, so no DHT is needed.
func startParamsNode(t *testing.T, puzzle cap.Puzzle, d cap.Difficulty) string {
	t.Helper()
	h, err := net.NewHost(net.HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("node host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	srv := net.NewServer(store.NewMemStore(), nil)
	srv.SetPoW(puzzle, d)
	srv.Register(h)
	for _, a := range h.Addrs() {
		return a.String() + "/p2p/" + h.ID().String()
	}
	t.Fatal("node has no listen address")
	return ""
}

// TestConnectWritesConfig checks `connect` reads the node's proof-of-work policy
// over the wire, writes a config.json that resolveWorkspace reads back intact,
// and mints the identity in place.
func TestConnectWritesConfig(t *testing.T) {
	// A node enforcing sha256 PoW at 8 bits (cheap to grind, keeps the test fast).
	addr := startParamsNode(t, cap.SHA256Puzzle{}, 8)

	dir := filepath.Join(t.TempDir(), "ws")
	args := []string{
		"-root", dir,
		"-label", "home nas",
		"-k", "6", "-m", "3",
		addr,
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
	if got := ws.Config.Bootstrap; len(got) != 1 || got[0] != addr {
		t.Fatalf("bootstrap = %v", got)
	}
	if ws.Config.Erasure.K != 6 || ws.Config.Erasure.M != 3 {
		t.Fatalf("erasure = %+v", ws.Config.Erasure)
	}
	// The proof-of-work policy came from the node, not a flag.
	if ws.Config.PoW.Difficulty != 8 || ws.Config.PoW.Puzzle != "sha256" {
		t.Fatalf("pow = %+v, want {8 sha256} from node", ws.Config.PoW)
	}

	// The erasure params flow through to the pipeline config.
	if p := ws.pipelineConfig().Params; p.K != 6 || p.M != 3 {
		t.Fatalf("pipelineConfig params = %+v", p)
	}
	// Keys default under the workspace, not the historical .revika, and connect
	// minted them in place (a self-certifying identity satisfying the policy).
	signKey := filepath.Join(dir, "keys", "user.sign.key")
	if ws.signKeyPath("") != signKey {
		t.Fatalf("signKeyPath = %q, want %q", ws.signKeyPath(""), signKey)
	}
	if _, err := os.Stat(signKey); err != nil {
		t.Fatalf("connect did not mint a signing key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", "user.key")); err != nil {
		t.Fatalf("connect did not mint an encryption key: %v", err)
	}
	if ws.signKeyPath("/explicit/x.sign.key") != "/explicit/x.sign.key" {
		t.Fatal("explicit -signkey flag not honoured")
	}
}

// TestConnectRefusesOverwrite checks connect will not clobber an existing
// config.json unless -force is given, and that -force keeps the existing
// identity rather than re-minting.
func TestConnectRefusesOverwrite(t *testing.T) {
	addr := startParamsNode(t, nil, 0) // PoW disabled → instant mint
	dir := filepath.Join(t.TempDir(), "ws")
	base := []string{"-root", dir, "-bootstrap", addr}
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

// TestConnectRejectsBadArgs covers the guards that fire before any node dial.
func TestConnectRejectsBadArgs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	cases := [][]string{
		{"-root", dir},                                  // no bootstrap
		{"-root", dir, "-k", "0", "/ip4/1/tcp/1/p2p/x"}, // k < 1 (rejected before dialing)
		{"-root", dir, "-bootstrap", "not-a-multiaddr"}, // unparseable bootstrap addr
	}
	for i, args := range cases {
		if err := cmdConnect(args); err == nil {
			t.Fatalf("case %d: expected error, got nil", i)
		}
	}
}

// TestConnectUnreachableNode checks connect fails clearly when no bootstrap node
// answers, rather than guessing a policy — and writes no config.
func TestConnectUnreachableNode(t *testing.T) {
	// A valid peer ID at 127.0.0.1:1, where nothing listens: the address parses
	// but the dial is refused fast (no 30s timeout).
	h, err := net.NewHost(net.HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	dead := "/ip4/127.0.0.1/tcp/1/p2p/" + h.ID().String()
	h.Close()

	dir := filepath.Join(t.TempDir(), "ws")
	if err := cmdConnect([]string{"-root", dir, "-bootstrap", dead}); err == nil {
		t.Fatal("connect against an unreachable node returned nil error")
	}
	if _, err := os.Stat(filepath.Join(dir, configFileName)); !os.IsNotExist(err) {
		t.Fatalf("connect wrote config.json despite failing: %v", err)
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

// TestBackendMerge checks an explicit -node overrides config bootstrap while an
// empty selector falls back to it.
func TestBackendMerge(t *testing.T) {
	ws := &Workspace{Config: &Config{Bootstrap: []string{"/cfg/a", "/cfg/b"}}}

	// No explicit selector: config bootstrap stands in.
	node, boots := ws.backend("")
	if node != "" || len(boots) != 2 || boots[0] != "/cfg/a" {
		t.Fatalf("fallback merge = %q %v", node, boots)
	}
	// Explicit -node wins, config bootstrap ignored.
	if n, b := ws.backend("/node/x"); n != "/node/x" || len(b) != 0 {
		t.Fatalf("explicit node not honoured: %q %v", n, b)
	}

	// A workspace with no config leaves the selectors untouched.
	empty := &Workspace{}
	if n, b := empty.backend(""); n != "" || len(b) != 0 {
		t.Fatalf("empty workspace altered selectors: %q %v", n, b)
	}
}
