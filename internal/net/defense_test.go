package net

import (
	"context"
	"strings"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func TestParseBlocklist(t *testing.T) {
	// Use a genuinely valid peer ID so peer.Decode accepts it.
	_, pub, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	in := strings.Join([]string{
		"# a comment line",
		"",
		"   ",
		"203.0.113.0/24",
		"2001:db8::/32",
		"198.51.100.7            # inline comment, bare IPv4",
		"2001:db8::1",
		pid.String() + "  # a peer",
	}, "\n")

	peers, subnets, err := ParseBlocklist(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseBlocklist: %v", err)
	}
	if len(peers) != 1 || peers[0] != pid {
		t.Fatalf("peers = %v, want [%s]", peers, pid)
	}
	// 2 CIDRs + 2 bare IPs (host routes).
	if len(subnets) != 4 {
		t.Fatalf("subnets = %d, want 4", len(subnets))
	}
	// Bare IPv4 must have become a /32 host route.
	if ones, bits := subnets[2].Mask.Size(); ones != 32 || bits != 32 {
		t.Fatalf("bare IPv4 mask = /%d (bits %d), want /32", ones, bits)
	}
	// Bare IPv6 must have become a /128 host route.
	if ones, bits := subnets[3].Mask.Size(); ones != 128 || bits != 128 {
		t.Fatalf("bare IPv6 mask = /%d (bits %d), want /128", ones, bits)
	}
}

func TestParseBlocklistInvalid(t *testing.T) {
	_, _, err := ParseBlocklist(strings.NewReader("not-a-peer-cidr-or-ip"))
	if err == nil {
		t.Fatal("expected error for unparseable line, got nil")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("error should name the line number: %v", err)
	}
}

func TestBlocklistGaterSubnet(t *testing.T) {
	_, subnets, err := ParseBlocklist(strings.NewReader("203.0.113.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	g := newBlocklistGater(nil, subnets, nil)

	blocked := ma.StringCast("/ip4/203.0.113.9/tcp/4001")
	allowed := ma.StringCast("/ip4/198.51.100.9/tcp/4001")

	if !g.blockedAddr(blocked) {
		t.Error("203.0.113.9 should be blocked by 203.0.113.0/24")
	}
	if g.blockedAddr(allowed) {
		t.Error("198.51.100.9 should not be blocked")
	}
}

// TestBlocklistGaterPeer exercises the peer-ID interception points directly.
// The inbound path (InterceptSecured) is checked here rather than end-to-end
// because a real dialer can observe its side as connected before the responder's
// post-handshake rejection closes the stream — a race that makes an e2e inbound
// assertion flaky. The outbound path (InterceptPeerDial) is deterministic and
// covered end-to-end below.
func TestBlocklistGaterPeer(t *testing.T) {
	_, pub, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, pub2, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := peer.IDFromPublicKey(pub2)
	if err != nil {
		t.Fatal(err)
	}

	g := newBlocklistGater([]peer.ID{blocked}, nil, nil)
	addr := ma.StringCast("/ip4/127.0.0.1/tcp/4001")

	if g.InterceptPeerDial(blocked) {
		t.Error("outbound dial to blocked peer should be denied")
	}
	if !g.InterceptPeerDial(allowed) {
		t.Error("outbound dial to allowed peer should be permitted")
	}
	if g.InterceptSecured(0, blocked, testConnAddrs{addr}) {
		t.Error("authenticated blocked peer should be denied")
	}
	if !g.InterceptSecured(0, allowed, testConnAddrs{addr}) {
		t.Error("authenticated allowed peer should be permitted")
	}
}

// testConnAddrs is a minimal network.ConnMultiaddrs for gater unit tests.
type testConnAddrs struct{ remote ma.Multiaddr }

func (c testConnAddrs) LocalMultiaddr() ma.Multiaddr  { return c.remote }
func (c testConnAddrs) RemoteMultiaddr() ma.Multiaddr { return c.remote }

// TestBlocklistGaterEndToEnd stands up two real hosts where the dialer's gater
// blocks the target's peer ID, and confirms the dial is refused outright.
func TestBlocklistGaterEndToEnd(t *testing.T) {
	server, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewHost(HostConfig{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		Defense:     &DefenseConfig{BlockPeers: []peer.ID{server.ID()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err == nil {
		t.Fatal("dial to blocked peer succeeded; gater did not reject it")
	}
}

// TestDefenseNoBlocklistConnects is the control: with defence enabled but an
// empty blocklist, a normal connection still succeeds.
func TestDefenseNoBlocklistConnects(t *testing.T) {
	client, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := NewHost(HostConfig{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		Defense:     &DefenseConfig{}, // resource + conn manager, no gater
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatalf("unblocked peer failed to connect: %v", err)
	}
}
