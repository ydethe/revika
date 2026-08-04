package net

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// Node self-defence (anti-DoS/DDoS). A revika node is dumb about *content*, not
// about its own availability: these are local, operator-controlled defences that
// act only on connection/identity metadata — a peer ID, an IP, a connection count
// — and never decrypt or interpret a shard, so the untrusted-blob-store trust
// model is untouched. Three layers, cheapest first:
//
//   - ResourceManager (rcmgr): hard per-scope caps on memory, streams, and
//     connections so one peer cannot exhaust the host.
//   - ConnManager: soft low/high connection watermarks; trims the least-useful
//     connections (after a grace period) once the count exceeds the high mark.
//   - ConnectionGater: a static, operator-supplied peer-ID / subnet blocklist,
//     refusing known-abusive peers at the transport layer before any protocol
//     handler runs.
//
// These pair with the write-path per-owner quota the ledger already enforces:
// the quota bounds *storage*, the defences here bound *connections and flow*.
//
// Defence controls (security/Defence.md; primitive P11 in security/frameworks.md):
//   D3-NTF (Network Traffic Filtering)   — ConnectionGater blocklist + rcmgr/connmgr caps.
//   D3-ITF (Inbound Traffic Filtering)   — inbound connections from blocked peers/subnets refused.
//   SC-7   (Boundary Protection)         — perimeter connection/flow limits. Compl. SC-5.
//   SC-5   (Denial-of-Service Protection) — connection watermarks bound resource exhaustion.

// Default connection-manager watermarks and grace period. Chosen to comfortably
// cover a small revika deployment (a handful of storage peers plus DHT churn)
// while still capping unbounded growth; tune via DefenseConfig for larger nodes.
const (
	defaultConnLow   = 64
	defaultConnHigh  = 192
	defaultConnGrace = 30 * time.Second
)

// DefenseConfig configures a node's self-defence layers. The zero value is
// usable: connection watermarks fall back to the defaults above and an empty
// blocklist installs no gater. It is consumed by NewHost via HostConfig.Defense.
type DefenseConfig struct {
	// BlockPeers are peer IDs refused on dial and on inbound connection.
	BlockPeers []peer.ID
	// BlockSubnets are IP networks (CIDR) whose addresses are refused. A bare
	// IP is stored as a host route (/32 or /128).
	BlockSubnets []*net.IPNet

	// ConnLow / ConnHigh are the connection-manager watermarks: the node keeps
	// at least ConnLow connections and starts trimming toward it once the count
	// exceeds ConnHigh. ConnHigh <= 0 disables the connection manager. When
	// ConnLow/ConnHigh are both zero the package defaults are used.
	ConnLow  int
	ConnHigh int
	// ConnGrace is how long a new connection is protected from trimming. Zero
	// uses the package default.
	ConnGrace time.Duration

	// Log receives one line per blocked connection (Debug, to stay quiet under a
	// flood) and the defence summary at startup. If nil, discarded.
	Log *slog.Logger
}

// defenseOptions turns cfg into the libp2p options that install the resource
// manager, connection manager, and (when the blocklist is non-empty) the
// connection gater, logging a one-line summary of what was enabled.
func defenseOptions(cfg *DefenseConfig) ([]libp2p.Option, error) {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	var opts []libp2p.Option

	// Resource manager: explicit fixed limiter built from libp2p's autoscaled
	// defaults (scaled to the machine's memory and FD budget). Making it explicit
	// — rather than relying on the implicit default — documents that a node runs
	// with hard per-scope resource caps and gives one place to tighten them.
	limiter := rcmgr.NewFixedLimiter(rcmgr.DefaultLimits.AutoScale())
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		return nil, fmt.Errorf("revika/net: resource manager: %w", err)
	}
	opts = append(opts, libp2p.ResourceManager(rm))

	// Connection manager: soft watermarks with a grace period so short-lived DHT
	// dials are not immediately reaped.
	low, high := cfg.ConnLow, cfg.ConnHigh
	if low == 0 && high == 0 {
		low, high = defaultConnLow, defaultConnHigh
	}
	grace := cfg.ConnGrace
	if grace == 0 {
		grace = defaultConnGrace
	}
	connMgrOn := high > 0
	if connMgrOn {
		cm, err := connmgr.NewConnManager(low, high, connmgr.WithGracePeriod(grace))
		if err != nil {
			return nil, fmt.Errorf("revika/net: connection manager: %w", err)
		}
		opts = append(opts, libp2p.ConnectionManager(cm))
	}

	// Connection gater: only installed when there is something to block.
	blocked := len(cfg.BlockPeers) + len(cfg.BlockSubnets)
	if blocked > 0 {
		opts = append(opts, libp2p.ConnectionGater(newBlocklistGater(cfg.BlockPeers, cfg.BlockSubnets, log)))
	}

	log.Info("defense enabled",
		"resource_manager", true,
		"conn_manager", connMgrOn,
		"conn_low", low,
		"conn_high", high,
		"blocked_peers", len(cfg.BlockPeers),
		"blocked_subnets", len(cfg.BlockSubnets))
	return opts, nil
}

// blocklistGater is a static ConnectionGater: it denies any connection to or
// from a blocklisted peer ID or an address inside a blocklisted subnet. It is
// consulted at every stage of connection establishment, so a blocked peer is
// refused whether we dial it or it dials us, and as early as the address is
// known (before the security handshake for inbound IPs).
type blocklistGater struct {
	peers   map[peer.ID]struct{}
	subnets []*net.IPNet
	log     *slog.Logger
}

func newBlocklistGater(peers []peer.ID, subnets []*net.IPNet, log *slog.Logger) *blocklistGater {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := make(map[peer.ID]struct{}, len(peers))
	for _, p := range peers {
		m[p] = struct{}{}
	}
	return &blocklistGater{peers: m, subnets: subnets, log: log}
}

func (g *blocklistGater) blockedPeer(p peer.ID) bool {
	_, ok := g.peers[p]
	return ok
}

// blockedAddr reports whether a's IP falls in any blocklisted subnet. Addresses
// with no IP component (or that fail to parse) are not blocked here — peer-ID
// gating still applies once the peer authenticates.
func (g *blocklistGater) blockedAddr(a ma.Multiaddr) bool {
	if len(g.subnets) == 0 || a == nil {
		return false
	}
	ip, err := manet.ToIP(a)
	if err != nil {
		return false
	}
	for _, sub := range g.subnets {
		if sub.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *blocklistGater) InterceptPeerDial(p peer.ID) bool {
	if g.blockedPeer(p) {
		g.log.Debug("defense: blocked outbound dial", "peer", p, "reason", "peer-blocklist")
		return false
	}
	return true
}

func (g *blocklistGater) InterceptAddrDial(p peer.ID, a ma.Multiaddr) bool {
	if g.blockedPeer(p) || g.blockedAddr(a) {
		return false
	}
	return true
}

func (g *blocklistGater) InterceptAccept(cma network.ConnMultiaddrs) bool {
	if g.blockedAddr(cma.RemoteMultiaddr()) {
		g.log.Debug("defense: blocked inbound connection", "addr", cma.RemoteMultiaddr(), "reason", "subnet-blocklist")
		return false
	}
	return true
}

func (g *blocklistGater) InterceptSecured(_ network.Direction, p peer.ID, cma network.ConnMultiaddrs) bool {
	if g.blockedPeer(p) {
		g.log.Debug("defense: blocked authenticated peer", "peer", p, "addr", cma.RemoteMultiaddr(), "reason", "peer-blocklist")
		return false
	}
	return !g.blockedAddr(cma.RemoteMultiaddr())
}

func (g *blocklistGater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

// ParseBlocklist parses a blocklist stream into peer IDs and IP subnets. Each
// non-empty line that is not a comment (leading '#') is either a libp2p peer ID
// (e.g. 12D3Koo…) or an IP range: a CIDR (203.0.113.0/24, 2001:db8::/32) or a
// bare IP (stored as a host route). Inline trailing comments after whitespace-'#'
// are stripped. An unrecognised token is reported with its 1-based line number.
func ParseBlocklist(r io.Reader) (peers []peer.ID, subnets []*net.IPNet, err error) {
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(stripComment(sc.Text()))
		if text == "" {
			continue
		}
		if _, cidr, perr := net.ParseCIDR(text); perr == nil {
			subnets = append(subnets, cidr)
			continue
		}
		if ip := net.ParseIP(text); ip != nil {
			subnets = append(subnets, hostRoute(ip))
			continue
		}
		if p, perr := peer.Decode(text); perr == nil {
			peers = append(peers, p)
			continue
		}
		return nil, nil, fmt.Errorf("revika/net: blocklist line %d: %q is not a peer ID, CIDR, or IP", line, text)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("revika/net: read blocklist: %w", err)
	}
	return peers, subnets, nil
}

// LoadBlocklistFile reads and parses the blocklist at path. A missing file is an
// error (a misconfigured path should fail loudly rather than silently disarm the
// defence); an empty or comment-only file parses to no entries.
func LoadBlocklistFile(path string) (peers []peer.ID, subnets []*net.IPNet, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("revika/net: open blocklist %s: %w", path, err)
	}
	defer f.Close()
	return ParseBlocklist(f)
}

// stripComment removes a trailing "# …" comment introduced by whitespace, while
// leaving a leading '#' (whole-line comment) for the caller to trim to "".
func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		// A '#' at the very start is a full-line comment; otherwise it must be
		// preceded by whitespace to count as an inline comment.
		if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
			return s[:i]
		}
	}
	return s
}

// hostRoute wraps a bare IP as a single-host CIDR (/32 for IPv4, /128 for IPv6).
func hostRoute(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}
