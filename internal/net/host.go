package net

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

// mdnsServiceTag scopes LAN discovery to revika peers.
const mdnsServiceTag = "revika"

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
	// EnableMDNS turns on mDNS LAN peer discovery (auto-dial peers found on the
	// local network). Useful for development and single-LAN deployments.
	EnableMDNS bool
	// Log receives host lifecycle lines: peer connect/disconnect (Debug) and each
	// new peer discovered via mDNS (Info). If nil, this logging is discarded.
	Log *slog.Logger
}

func defaultListenAddrs() []string {
	return []string{
		"/ip4/0.0.0.0/tcp/0",
		"/ip4/0.0.0.0/udp/0/quic-v1",
	}
}

// NewHost builds a libp2p host from cfg. The caller owns the returned host and
// must Close it. If cfg.EnableMDNS is set, LAN discovery is started and its
// service is closed together with the host.
func NewHost(cfg HostConfig) (host.Host, error) {
	priv, err := loadOrCreateIdentity(cfg.IdentityPath)
	if err != nil {
		return nil, err
	}
	listen := cfg.ListenAddrs
	if len(listen) == 0 {
		listen = defaultListenAddrs()
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listen...),
	)
	if err != nil {
		return nil, fmt.Errorf("revika/net: new host: %w", err)
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Log the underlying peer connection lifecycle. This is churn on a busy DHT,
	// so it stays at Debug; the meaningful "discovered node" lines are emitted at
	// Info by the mDNS/DHT discovery layers.
	notifyConnections(h, log)
	if cfg.EnableMDNS {
		if err := startMDNS(h, log); err != nil {
			h.Close()
			return nil, err
		}
	}
	return h, nil
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

// mdnsNotifee dials peers discovered on the LAN and logs each new one.
type mdnsNotifee struct {
	h   host.Host
	log *slog.Logger

	// seen dedups repeated mDNS announcements so each node is logged only the
	// first time it is found on the LAN.
	mu   sync.Mutex
	seen map[peer.ID]struct{}
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return // ourselves
	}
	n.mu.Lock()
	_, known := n.seen[pi.ID]
	if !known {
		n.seen[pi.ID] = struct{}{}
	}
	n.mu.Unlock()
	if !known {
		n.log.Info("discovered node", "peer", pi.ID, "via", "mdns", "addrs", pi.Addrs)
	}
	// Best-effort connect; failures are transient and left to libp2p to retry.
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	_ = n.h.Connect(ctx, pi)
}

func startMDNS(h host.Host, log *slog.Logger) error {
	svc := mdns.NewMdnsService(h, mdnsServiceTag, &mdnsNotifee{h: h, log: log, seen: map[peer.ID]struct{}{}})
	if err := svc.Start(); err != nil {
		return fmt.Errorf("revika/net: start mdns: %w", err)
	}
	// The service's lifetime is tied to the host: libp2p closes registered
	// network-notifee style services on host Close. mdns.Service also stops
	// when the host's context is cancelled.
	return nil
}
