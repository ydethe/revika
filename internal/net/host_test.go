package net

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func TestGenerateIdentityFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "node.key")

	id, err := GenerateIdentityFile(path)
	if err != nil {
		t.Fatalf("GenerateIdentityFile: %v", err)
	}
	if id == "" {
		t.Fatal("empty peer ID")
	}

	// The key must be persisted at 0600 and reload to the SAME peer ID (so the
	// printed SEED_ADDR matches the identity a node loads from the file).
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600", perm)
	}
	priv, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("reload identity: %v", err)
	}
	reloaded, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("peer ID from reloaded key: %v", err)
	}
	if reloaded != id {
		t.Errorf("reloaded peer ID = %s, want %s", reloaded, id)
	}

	// Two fresh keys differ (no fixed/committed identity).
	other, err := GenerateIdentityFile(filepath.Join(dir, "other.key"))
	if err != nil {
		t.Fatalf("second GenerateIdentityFile: %v", err)
	}
	if other == id {
		t.Error("two generated identities collided")
	}

	// It must refuse to clobber an existing key (never silently replace a live one).
	if _, err := GenerateIdentityFile(path); err == nil {
		t.Error("expected an error overwriting an existing key, got nil")
	}
}

func TestPublicAddrsFactory(t *testing.T) {
	factory, err := publicAddrsFactory("203.0.113.7")
	if err != nil {
		t.Fatalf("build factory: %v", err)
	}

	in := []ma.Multiaddr{
		ma.StringCast("/ip4/0.0.0.0/tcp/4001"),
		ma.StringCast("/ip4/192.168.1.5/udp/4001/quic-v1"),
	}
	out := factory(in)

	got := make(map[string]bool, len(out))
	for _, a := range out {
		got[a.String()] = true
	}

	// Every listen address keeps a public-IP variant (transport/port preserved)…
	for _, want := range []string{
		"/ip4/203.0.113.7/tcp/4001",
		"/ip4/203.0.113.7/udp/4001/quic-v1",
	} {
		if !got[want] {
			t.Errorf("missing public variant %q in %v", want, out)
		}
	}
	// …and the originals are retained.
	for _, orig := range in {
		if !got[orig.String()] {
			t.Errorf("missing original %q in %v", orig, out)
		}
	}
	// Public variants come first so peers prefer the routable address.
	if !strings.HasPrefix(out[0].String(), "/ip4/203.0.113.7/") {
		t.Errorf("first advertised addr = %q, want a public variant", out[0])
	}
}

func TestPublicAddrsFactoryIPv6(t *testing.T) {
	factory, err := publicAddrsFactory("2001:db8::1")
	if err != nil {
		t.Fatalf("build factory: %v", err)
	}
	out := factory([]ma.Multiaddr{ma.StringCast("/ip6/::/tcp/4001")})
	found := false
	for _, a := range out {
		if a.String() == "/ip6/2001:db8::1/tcp/4001" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing IPv6 public variant in %v", out)
	}
}

func TestPublicAddrsFactoryInvalid(t *testing.T) {
	if _, err := publicAddrsFactory("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid public IP")
	}
}

func TestNewHostAdvertisesPublicIP(t *testing.T) {
	h, err := NewHost(HostConfig{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		PublicIP:    "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { h.Close() })

	for _, a := range h.Addrs() {
		if strings.HasPrefix(a.String(), "/ip4/203.0.113.7/tcp/") {
			return
		}
	}
	t.Errorf("host does not advertise public IP; addrs = %v", h.Addrs())
}
