package net

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
)

// Defence controls (security/Defence.md; primitives P17, P24 in security/frameworks.md):
//   SC-8  (Transmission Confidentiality and Integrity) — partial: libp2p's default transport
//         encryption/authentication (Noise/TLS) is inherited, not pinned here (see Defence.md notes).
//   SC-12 (Cryptographic Key Establishment and Management) — the node identity key is persisted
//         0600 under its own 0700 dir and never transmitted.

// HostConfig configures a libp2p host.
type HostConfig struct {
	// ListenAddrs are multiaddrs to listen on. If empty, a sensible default
	// (all interfaces, OS-assigned TCP + QUIC ports) is used.
	ListenAddrs []string
	// IdentityPath is where the node's persistent Ed25519 identity key lives.
	// If the file exists it is loaded; otherwise a fresh key is generated and
	// written there (0600). The PeerID derived from this key is the node's
	// stable network identity across restarts.
	IdentityPath string
	// PublicIP, when set, is the node's externally reachable IP address (IPv4 or
	// IPv6). A node behind NAT only observes private/unspecified listen addresses,
	// so peers cannot dial it from the WAN. Setting this installs an address
	// factory that advertises, for every listen address, a public variant with the
	// IP replaced by PublicIP and the transport/port preserved. This assumes the
	// public port equals the bound port (e.g. a 1:1 port forward), which holds for
	// fixed -listen ports mapped straight through. Empty leaves libp2p's observed
	// addresses untouched.
	PublicIP string
	// Defense, when non-nil, installs the node's self-defence layers (resource
	// manager, connection manager, and a static blocklist gater) on the host —
	// see defense.go. Nil (the default, used by tests) leaves libp2p's own
	// defaults in place and installs no gater.
	Defense *DefenseConfig
	// Log receives host lifecycle lines: peer connect/disconnect (Debug). If nil,
	// this logging is discarded.
	Log *slog.Logger
}

func defaultListenAddrs() []string {
	return []string{
		"/ip4/0.0.0.0/tcp/0",
		"/ip4/0.0.0.0/udp/0/quic-v1",
	}
}

// NewHost builds a libp2p host from cfg. The caller owns the returned host and
// must Close it.
func NewHost(cfg HostConfig) (host.Host, error) {
	priv, err := loadOrCreateIdentity(cfg.IdentityPath)
	if err != nil {
		return nil, err
	}
	listen := cfg.ListenAddrs
	if len(listen) == 0 {
		listen = defaultListenAddrs()
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listen...),
	}
	// Advertise a public IP for a NAT'd node so WAN peers can dial it. When set,
	// every listen address gains a public-IP variant in the addresses the host
	// announces (and thus in the DHT and on /status's bootstrap strings).
	if cfg.PublicIP != "" {
		factory, err := publicAddrsFactory(cfg.PublicIP)
		if err != nil {
			return nil, err
		}
		opts = append(opts, libp2p.AddrsFactory(factory))
	}
	// Node self-defence: resource manager + connection manager + optional static
	// blocklist gater. Only wired when the caller asks for it (nodes do; tests
	// leave it nil and run on libp2p defaults).
	if cfg.Defense != nil {
		if cfg.Defense.Log == nil {
			cfg.Defense.Log = log
		}
		defOpts, err := defenseOptions(cfg.Defense)
		if err != nil {
			return nil, err
		}
		opts = append(opts, defOpts...)
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("revika/net: new host: %w", err)
	}
	// Log the underlying peer connection lifecycle. This is churn on a busy DHT,
	// so it stays at Debug; the meaningful "discovered node" lines are emitted at
	// Info by the DHT discovery layer.
	notifyConnections(h, log)
	return h, nil
}

// publicAddrsFactory builds a libp2p address factory that advertises a public-IP
// variant of every listen address alongside the originals. For each announced
// multiaddr whose leading component is an IPv4/IPv6 address, it emits a copy with
// that IP swapped for publicIP and the remaining transport/port kept intact, so a
// NAT'd node (which only observes private/unspecified addresses) still tells peers
// a dialable WAN address. The public variants are listed first; duplicates are
// dropped. It errors if publicIP is not a valid IP literal.
func publicAddrsFactory(publicIP string) (func([]ma.Multiaddr) []ma.Multiaddr, error) {
	ip := net.ParseIP(publicIP)
	if ip == nil {
		return nil, fmt.Errorf("revika/net: invalid public IP %q", publicIP)
	}
	proto := "ip6"
	if ip.To4() != nil {
		proto = "ip4"
	}
	pub, err := ma.NewComponent(proto, ip.String())
	if err != nil {
		return nil, fmt.Errorf("revika/net: build public addr %q: %w", publicIP, err)
	}

	return func(addrs []ma.Multiaddr) []ma.Multiaddr {
		out := make([]ma.Multiaddr, 0, len(addrs)*2)
		seen := make(map[string]struct{}, len(addrs)*2)
		add := func(a ma.Multiaddr) {
			s := a.String()
			if _, dup := seen[s]; dup {
				return
			}
			seen[s] = struct{}{}
			out = append(out, a)
		}
		// Public variants first so peers prefer the routable address.
		for _, a := range addrs {
			first, rest := ma.SplitFirst(a)
			if rest == nil || first == nil {
				continue
			}
			if code := first.Protocol().Code; code == ma.P_IP4 || code == ma.P_IP6 {
				add(pub.Encapsulate(rest))
			}
		}
		for _, a := range addrs {
			add(a)
		}
		return out
	}, nil
}

// notifyConnections wires a network notifiee that logs each transport-level peer
// connection and disconnection the host handles.
func notifyConnections(h host.Host, log *slog.Logger) {
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			log.Debug("peer connected",
				"peer", c.RemotePeer(), "addr", c.RemoteMultiaddr(), "dir", c.Stat().Direction)
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			log.Debug("peer disconnected",
				"peer", c.RemotePeer(), "addr", c.RemoteMultiaddr())
		},
	})
}

// loadOrCreateIdentity loads the Ed25519 private key at path, creating and
// persisting a fresh one if the file does not exist. An empty path means an
// ephemeral in-memory key (a new identity every run) — handy for tests.
func loadOrCreateIdentity(path string) (libp2pcrypto.PrivKey, error) {
	if path == "" {
		priv, _, err := libp2pcrypto.GenerateEd25519Key(nil)
		if err != nil {
			return nil, fmt.Errorf("revika/net: generate ephemeral identity: %w", err)
		}
		return priv, nil
	}
	data, err := os.ReadFile(path)
	if err == nil {
		priv, err := libp2pcrypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("revika/net: parse identity %s: %w", path, err)
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("revika/net: read identity %s: %w", path, err)
	}

	// Not present yet — generate, persist, and return.
	priv, _, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, fmt.Errorf("revika/net: generate identity: %w", err)
	}
	raw, err := libp2pcrypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("revika/net: marshal identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("revika/net: create identity dir: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("revika/net: write identity %s: %w", path, err)
	}
	return priv, nil
}
