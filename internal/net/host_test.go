package net

import (
	"strings"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

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
