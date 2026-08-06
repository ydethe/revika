package net

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/host"
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

	// Blocklister, when non-nil, supplies a *mutable* connection gater so the
	// runtime abuse detector can blacklist a misbehaving peer after startup and
	// persist it. It supersedes BlockPeers/BlockSubnets: the operator's static
	// entries are unioned into the Blocklister at construction, not installed
	// separately. Left nil, the static BlockPeers/BlockSubnets path is used (the
	// mode tests and a defence-less node run in).
	Blocklister *Blocklister

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

	// Connection gater: a mutable Blocklister (runtime-extensible) takes precedence;
	// failing that, the static operator blocklist, and only when non-empty.
	var (
		blockedPeers   = len(cfg.BlockPeers)
		blockedSubnets = len(cfg.BlockSubnets)
	)
	if cfg.Blocklister != nil {
		opts = append(opts, libp2p.ConnectionGater(cfg.Blocklister.gater))
		blockedPeers, blockedSubnets = cfg.Blocklister.counts()
	} else if blockedPeers+blockedSubnets > 0 {
		opts = append(opts, libp2p.ConnectionGater(newBlocklistGater(cfg.BlockPeers, cfg.BlockSubnets, log)))
	}

	log.Info("defense enabled",
		"resource_manager", true,
		"conn_manager", connMgrOn,
		"conn_low", low,
		"conn_high", high,
		"blocked_peers", blockedPeers,
		"blocked_subnets", blockedSubnets,
		"auto_blocklist", cfg.Blocklister != nil)
	return opts, nil
}

// blocklistGater is a ConnectionGater: it denies any connection to or from a
// blocklisted peer ID or an address inside a blocklisted subnet. It is consulted
// at every stage of connection establishment, so a blocked peer is refused
// whether we dial it or it dials us, and as early as the address is known (before
// the security handshake for inbound IPs).
//
// The subnet list is fixed at construction (operator policy), but the peer-ID set
// is mutable and mutex-guarded so the runtime abuse detector can add a peer via
// Blocklister.Block while the gater is live. The gater refuses only *future*
// connection attempts — an already-open connection is closed separately (see
// Blocklister.Block).
type blocklistGater struct {
	mu      sync.RWMutex
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

// addPeer adds p to the blocked set. Reports whether it was newly added (false if
// already blocked), so a caller can avoid duplicate persistence/logging.
func (g *blocklistGater) addPeer(p peer.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.peers[p]; ok {
		return false
	}
	g.peers[p] = struct{}{}
	return true
}

func (g *blocklistGater) blockedPeer(p peer.ID) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.peers[p]
	return ok
}

// counts reports the number of blocked peer IDs and subnets, for the startup
// defence summary.
func (g *blocklistGater) counts() (peers, subnets int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.peers), len(g.subnets)
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

// Blocklister is a runtime-extensible peer blocklist: a mutable connection gater
// backed by a persistent flat file. It seeds from the operator's static blocklist
// (peer IDs + subnets from -blocklist) unioned with an on-disk auto-blocklist a
// prior run's abuse detector appended to, so a peer banned in one run stays banned
// across restarts. Block() bans a peer at runtime — it extends the gater (refusing
// the peer's *future* connections), appends the peer ID to the auto file, and
// closes any live connection to it (the gater alone would leave an established
// connection open).
//
// The auto file uses the same one-token-per-line format as ParseBlocklist (peer
// IDs / CIDR / IP, '#' comments), so an operator can read, hand-edit, or fold it
// into -blocklist. Block only ever appends peer IDs — identity is the unit the
// detector acts on; subnet rules remain operator policy via -blocklist.
type Blocklister struct {
	gater    *blocklistGater
	autoPath string
	log      *slog.Logger

	mu sync.Mutex
	h  host.Host // set post-construction via SetHost; used to close a banned peer
}

// NewBlocklister builds a Blocklister seeded with the operator's static peer IDs
// and subnets plus the persisted auto-blocklist at autoPath (if it exists — a
// missing file is fine, it is created on the first Block). autoPath may be empty
// to keep an in-memory-only blocklist (no persistence across restarts).
func NewBlocklister(operatorPeers []peer.ID, operatorSubnets []*net.IPNet, autoPath string, log *slog.Logger) (*Blocklister, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	peers := append([]peer.ID(nil), operatorPeers...)
	subnets := append([]*net.IPNet(nil), operatorSubnets...)
	if autoPath != "" {
		if _, err := os.Stat(autoPath); err == nil {
			ap, as, perr := LoadBlocklistFile(autoPath)
			if perr != nil {
				return nil, fmt.Errorf("revika/net: load auto-blocklist: %w", perr)
			}
			peers = append(peers, ap...)
			subnets = append(subnets, as...)
			log.Info("auto-blocklist loaded", "path", autoPath, "peers", len(ap), "subnets", len(as))
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("revika/net: stat auto-blocklist %s: %w", autoPath, err)
		}
	}
	return &Blocklister{
		gater:    newBlocklistGater(peers, subnets, log),
		autoPath: autoPath,
		log:      log,
	}, nil
}

// SetHost gives the Blocklister the live host so Block can drop an existing
// connection to a newly-banned peer (the gater only refuses future ones). Call
// once, after NewHost. Safe to leave unset — banning then only bars reconnection.
func (b *Blocklister) SetHost(h host.Host) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.h = h
}

// counts reports the current blocked peer/subnet totals, for the defence summary.
func (b *Blocklister) counts() (peers, subnets int) { return b.gater.counts() }

// Blocked reports whether p is currently blocked. Exposed for tests and callers
// that want to avoid redundant work on an already-banned peer.
func (b *Blocklister) Blocked(p peer.ID) bool { return b.gater.blockedPeer(p) }

// Block bans peer p for the given reason: it is added to the live gater, appended
// to the persistent auto-blocklist, and its current connections are closed. It is
// idempotent — a peer already blocked is a no-op (no duplicate persistence). A
// persistence failure is logged but does not fail the ban (the in-memory gater
// still refuses the peer for this run).
func (b *Blocklister) Block(p peer.ID, reason string) {
	if !b.gater.addPeer(p) {
		return // already blocked
	}
	b.log.Warn("defense: peer blacklisted", "event", "defense.blacklist", "peer", p, "reason", reason)
	if b.autoPath != "" {
		if err := b.appendAuto(p, reason); err != nil {
			b.log.Warn("defense: persist blacklist entry", "event", "defense.blacklist_persist_failed", "peer", p, "err", err)
		}
	}
	b.mu.Lock()
	h := b.h
	b.mu.Unlock()
	if h != nil {
		if err := h.Network().ClosePeer(p); err != nil {
			b.log.Debug("defense: close banned peer", "peer", p, "err", err)
		}
	}
}

// appendAuto appends one peer-ID line (with the reason as a trailing comment) to
// the auto-blocklist file, creating it and its directory if needed. The whole
// line is written in a single call so a concurrent reader/restart never sees a
// half-written token.
func (b *Blocklister) appendAuto(p peer.ID, reason string) error {
	if err := os.MkdirAll(filepath.Dir(b.autoPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(b.autoPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line := fmt.Sprintf("%s  # auto: %s\n", p.String(), sanitizeComment(reason))
	_, err = f.WriteString(line)
	return err
}

// sanitizeComment strips newlines and '#' from a reason so it stays a single,
// well-formed trailing comment in the auto-blocklist file.
func sanitizeComment(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "#", "").Replace(s)
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
