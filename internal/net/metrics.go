package net

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"

	"revika/internal/geoip"
	"revika/internal/ledger"
)

// metricsShutdownTimeout bounds how long Serve waits for in-flight requests to
// drain when the context is cancelled.
const metricsShutdownTimeout = 5 * time.Second

// MetricsServer exposes a node's operational state over plain HTTP. It is meant
// to sit behind a reverse proxy (e.g. Traefik) that terminates TLS, so it speaks
// HTTP only. It serves:
//
//	GET /healthz   liveness  — 200 as soon as the process is up
//	GET /readyz    readiness — 200 once the node can serve (DHT routing table
//	               non-empty when the DHT is on; always ready otherwise)
//	GET /status    JSON snapshot: general info (version, build date, proof-of-work
//	               admission policy), storage accounting, and the node's view of
//	               the network (peer cartography)
//	GET /metrics   Prometheus text-exposition metrics
//	GET /admin     rich HTML operator dashboard for this node: a self view (the
//	               full /status snapshot rendered as HTML), the active connection
//	               blocklist (SetBlocklister), the shards this node stores (from the
//	               ledger stripe index), a detailed peer list (the serving node
//	               leads, chipped apart), and a geographic map (OpenStreetMap via
//	               Leaflet) plotting each node at its estimated position
//	               (SetGeolocator)
//
// It reads live state from the host, the ledger, and (optionally) the DHT
// Discovery; it holds no state of its own beyond the start time and version.
//
// Defence controls (security/Defence.md; primitive P27 in security/frameworks.md):
//
//	AU-6 (Audit Record Review, Analysis, and Reporting) — partial: exposes Prometheus metrics
//	     and a JSON status snapshot for external review; no in-node analysis/alerting (Defence.md notes).
type MetricsServer struct {
	h         host.Host
	led       *ledger.Ledger
	disc      *Discovery // optional: nil when the node runs without the DHT
	gc        *GCStats   // optional: nil when GC activity is not tracked
	version   string
	buildDate string
	started   time.Time
	pow       PoWInfo       // proof-of-work admission policy this node enforces on writes
	repair    RepairInfo    // repair maintenance policy this node runs (and advertises)
	rebalance RebalanceInfo // rebalance maintenance policy this node runs (and advertises)
	defense   DefenseInfo   // local abuse controls (Axis A/B + per-owner write cap)
	loadSrc   LoadSource    // optional: reports storage capacity/load for rebalancing (§3.4)
	protocols []string      // versioned libp2p stream protocols this node serves
	geo       geoip.Locator // optional: estimates a peer's position for the /admin map (nil = positions unknown)
	blocklist *Blocklister  // optional: the live connection blocklist, surfaced on /admin (nil = not shown)
	log       *slog.Logger
}

// NewMetricsServer builds a MetricsServer. disc may be nil (no DHT); led must be
// non-nil. version and buildDate are reported verbatim in /status and /metrics.
// started is the process start time, used to report uptime.
func NewMetricsServer(h host.Host, led *ledger.Ledger, disc *Discovery, version, buildDate string, started time.Time, log *slog.Logger) *MetricsServer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &MetricsServer{h: h, led: led, disc: disc, version: version, buildDate: buildDate, started: started, log: log}
}

// SetGCStats attaches a garbage-collector stats collector so /status and
// /metrics report GC activity. Optional; call before Serve.
func (m *MetricsServer) SetGCStats(gc *GCStats) { m.gc = gc }

// SetLoadSource attaches the node's storage-load reporter so /status and
// /metrics expose the capacity, free bytes, and normalized load the rebalancer
// balances on (Architecture §3.4). Optional; call before Serve. Left unset, the
// capacity/free/load fields report 0 (capacity unknown).
func (m *MetricsServer) SetLoadSource(src LoadSource) { m.loadSrc = src }

// SetPoW records the proof-of-work admission policy the node enforces on writes
// so it is reported on /status and /metrics. minBits is the required
// leading-zero-bit difficulty; the puzzle is always Argon2id. A zero minBits
// means proof-of-work admission is disabled. Optional; call before Serve.
func (m *MetricsServer) SetPoW(minBits uint) {
	if minBits == 0 {
		m.pow = PoWInfo{} // disabled
		return
	}
	m.pow = PoWInfo{Enabled: true, Difficulty: minBits}
}

// SetProtocols records the versioned libp2p stream protocols this node serves so
// they are reported on /status (protocols) and /metrics (revika_protocol_info),
// letting an operator confirm the wire versions a node speaks. revika is
// pre-release, so peers must run matching versions. Optional; call before Serve.
func (m *MetricsServer) SetProtocols(ps []protocol.ID) {
	m.protocols = make([]string, 0, len(ps))
	for _, p := range ps {
		m.protocols = append(m.protocols, string(p))
	}
	sort.Strings(m.protocols)
}

// SetGeolocator attaches the position estimator the /admin dashboard uses to
// place connected peers on its map. Optional; left unset (nil), the map renders
// with no markers and the list still shows every peer — positions simply read
// "unknown". Call before Serve.
func (m *MetricsServer) SetGeolocator(g geoip.Locator) { m.geo = g }

// SetBlocklister attaches the live connection blocklist so the /admin dashboard
// can display the peer IDs and subnets this node currently refuses (operator
// static entries unioned with the abuse detector's runtime auto-bans). Optional;
// left unset (nil), the blocklist panel reports that no blocklist is configured.
// It is read-only — the dashboard shows the set, it never mutates it. Call before
// Serve.
func (m *MetricsServer) SetBlocklister(b *Blocklister) { m.blocklist = b }

// SetMaintenance records the repair and rebalancing policy this node runs so it
// is reported on /status and (via the params protocol) advertised to joining
// peers. A joining node that inherited its policy passes the same effective
// values here, so the surface reflects what the node actually does. Optional;
// call before Serve.
func (m *MetricsServer) SetMaintenance(repair RepairInfo, rebalance RebalanceInfo) {
	m.repair, m.rebalance = repair, rebalance
}

// SetDefenses records the node's local abuse-control configuration (Axis A
// per-subnet flow cap, the per-owner write-verb cap, and Axis B age-graduated
// quota) so it is reported on /status, /metrics, and the /admin dashboard. These
// are per-node local policy, never inherited from bootstrap, so the surface shows
// exactly what this node enforces. Optional; call before Serve.
func (m *MetricsServer) SetDefenses(d DefenseInfo) { m.defense = d }

// Handler returns the HTTP mux serving the metrics endpoints. Exposed so it can
// be tested directly (via httptest) and mounted by a caller if desired.
func (m *MetricsServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", m.handleHealthz)
	mux.HandleFunc("/readyz", m.handleReadyz)
	mux.HandleFunc("/status", m.handleStatus)
	mux.HandleFunc("/metrics", m.handleMetrics)
	mux.HandleFunc("/admin", m.handleAdmin)
	return mux
}

// Serve runs the HTTP server on addr (e.g. ":9096" or "127.0.0.1:9096") until
// ctx is cancelled, then shuts it down gracefully. It blocks; run it in a
// goroutine. A nil or empty addr is a programming error.
func (m *MetricsServer) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           m.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Shut the server down when the process context is cancelled.
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	m.log.Info("metrics: http server listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("revika/net: metrics server: %w", err)
	}
	return nil
}

// ---- Payload types (stable JSON shape for /status) ----

// Status is the JSON body returned by /status.
type Status struct {
	PeerID        string   `json:"peer_id"`
	Version       string   `json:"version"`
	BuildDate     string   `json:"build_date"`
	UptimeSeconds float64  `json:"uptime_seconds"`
	ListenAddrs   []string `json:"listen_addrs"`
	// Bootstrap holds this node's dialable addresses each terminated with
	// /p2p/<peer-id>: ready to paste into `revika-ctl -bootstrap <addr>` to join
	// the network through this node. Mirrors ListenAddrs with the peer ID attached.
	Bootstrap []string `json:"bootstrap"`
	// Protocols are the versioned libp2p stream protocols this node serves (e.g.
	// /revika/shard/1.2.0). revika is pre-release: peers must run matching versions.
	Protocols []string      `json:"protocols"`
	PoW       PoWInfo       `json:"pow"`
	Repair    RepairInfo    `json:"repair"`
	Rebalance RebalanceInfo `json:"rebalance"`
	Defense   DefenseInfo   `json:"defense"`
	Storage   StorageInfo   `json:"storage"`
	Network   NetworkInfo   `json:"network"`
	GC        GCSnapshot    `json:"gc"`
}

// DefenseInfo reports a node's *local* abuse-control configuration — the flow and
// storage-capability caps that are chosen per node and never inherited from
// bootstrap (unlike the PoW/repair/rebalance cluster policy above). It gathers the
// three levers a node runs against flooding and Sybil abuse:
//
//   - SubnetRateLimit (Axis A): an identity-agnostic per-subnet request-rate cap
//     that bounds a flood from one network location regardless of how many owner
//     identities it mints.
//   - WriteRateLimit: a per-owner token bucket on the write verbs (PUT/DELETE).
//   - QuotaRamp (Axis B): an age-graduated per-owner storage quota, so a freshly
//     minted (e.g. re-minted-after-ban) identity starts near-powerless.
//
// Each sub-policy carries its own Enabled flag so the surface distinguishes "off"
// from "on with these parameters".
type DefenseInfo struct {
	SubnetRateLimit SubnetLimitInfo `json:"subnet_rate_limit"` // Axis A
	WriteRateLimit  WriteLimitInfo  `json:"write_rate_limit"`
	QuotaRamp       QuotaRampInfo   `json:"quota_ramp"` // Axis B
}

// SubnetLimitInfo is the Axis A per-subnet flow cap: a token bucket keyed on the
// source IP subnet metering every shard/probe request. Rate is the sustained
// requests/second a subnet may make, Burst the back-to-back allowance, and
// Prefix4/Prefix6 the IPv4/IPv6 prefix lengths that aggregate source IPs into one
// bucket. Enabled is false when the cap is off.
type SubnetLimitInfo struct {
	Enabled bool    `json:"enabled"`
	Rate    float64 `json:"rate_per_second"`
	Burst   float64 `json:"burst"`
	Prefix4 int     `json:"prefix4"`
	Prefix6 int     `json:"prefix6"`
}

// WriteLimitInfo is the per-owner write-verb rate cap: a token bucket keyed on the
// Ed25519 owner refusing over-rate PUT/DELETE (grant-authorized maintenance
// exempt). Enabled is false when the cap is off.
type WriteLimitInfo struct {
	Enabled bool    `json:"enabled"`
	Rate    float64 `json:"rate_per_second"`
	Burst   float64 `json:"burst"`
}

// QuotaRampInfo is the Axis B age-graduated per-owner quota: an owner's effective
// storage ceiling rises from InitialFraction of the full quota at first sight to the
// full quota once its age reaches Ramp. Enabled is false when no ramp is in force
// (no ramp duration, an out-of-range fraction, or no per-owner quota to graduate).
type QuotaRampInfo struct {
	Enabled         bool          `json:"enabled"`
	Ramp            time.Duration `json:"ramp"`             // age at which the full quota is reached (0 = no ramp)
	InitialFraction float64       `json:"initial_fraction"` // fraction of the full quota at age zero
}

// PoWInfo is the proof-of-work admission policy this node enforces on writes:
// an owner identity must be self-certifying (Argon2id) with at least Difficulty
// leading zero bits, or its writes are refused. Enabled is false (and Difficulty
// 0) when proof-of-work admission is off. The puzzle is always Argon2id, so it is
// not carried on the wire.
type PoWInfo struct {
	Enabled    bool `json:"enabled"`
	Difficulty uint `json:"difficulty"` // required leading zero bits (0 = disabled)
}

// RepairInfo is the availability-repair maintenance policy a node runs and
// advertises over the params protocol, so a joining node inherits whether repair
// runs and how often instead of re-typing it. Enabled is false (Interval 0) when
// the node runs no repair loop. Interval marshals as nanoseconds on the wire and
// round-trips between revika nodes.
type RepairInfo struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"` // period between repair sweeps (0 = disabled)
}

// RebalanceInfo is the storage-rebalancing maintenance policy (Architecture §3.4)
// a node runs and advertises over the params protocol, so a joining node inherits
// the cluster's diffusion schedule. Enabled is false when the node runs no
// rebalance loop. Interval is the period between sweeps and Threshold the load-gap
// dead-band below which no shard is moved. The schedule (Interval) also bounds how
// often a well-behaved peer may initiate rebalancing, which the receive-side abuse
// detector polices.
type RebalanceInfo struct {
	Enabled   bool          `json:"enabled"`
	Interval  time.Duration `json:"interval"`  // period between rebalance sweeps (0 = disabled)
	Threshold float64       `json:"threshold"` // load-gap dead-band in [0,1]
}

// StorageInfo is the accounting side of /status: what this node holds and for whom.
type StorageInfo struct {
	Shards     int64 `json:"shards"`      // distinct shards stored
	BytesUsed  int64 `json:"bytes_used"`  // physical bytes across all shards
	QuotaBytes int64 `json:"quota_bytes"` // per-owner quota (0 = unlimited)
	Clients    int   `json:"clients"`     // distinct owners storing shards
	// Capacity/Free/Load are the rebalancing signal (§3.4), populated when a load
	// source is configured: CapacityBytes is the usable storage budget
	// (min of free disk / operator budget; 0 = unknown), FreeBytes the remainder,
	// and Load the normalized fraction used in [0,1] the diffusion balancer equalizes.
	CapacityBytes int64       `json:"capacity_bytes"`
	FreeBytes     int64       `json:"free_bytes"`
	Load          float64     `json:"load"`
	Owners        []OwnerInfo `json:"owners"` // per-owner breakdown, largest first
}

// OwnerInfo is one client's accounting; Owner is the base64 (raw std) public key.
type OwnerInfo struct {
	Owner      string `json:"owner"`
	BytesUsed  int64  `json:"bytes_used"`
	ShardCount int    `json:"shard_count"`
}

// NetworkInfo is the cartography side of /status: the node's view of the network.
type NetworkInfo struct {
	Connected        int        `json:"connected_peers"`
	RoutingTableSize int        `json:"routing_table_size"`
	DHT              bool       `json:"dht"`
	Peers            []PeerInfo `json:"peers"`
}

// PeerInfo describes one currently connected peer.
type PeerInfo struct {
	ID        string   `json:"id"`
	Addrs     []string `json:"addrs"`
	Direction string   `json:"direction"` // "inbound" | "outbound" | "unknown"
}

// snapshot gathers the live state once so /status and /metrics agree.
func (m *MetricsServer) snapshot() (Status, error) {
	st := Status{
		PeerID:        m.h.ID().String(),
		Version:       m.version,
		BuildDate:     m.buildDate,
		UptimeSeconds: time.Since(m.started).Seconds(),
		Protocols:     m.protocols,
		PoW:           m.pow,
		Repair:        m.repair,
		Rebalance:     m.rebalance,
		Defense:       m.defense,
	}
	id := m.h.ID().String()
	for _, a := range m.h.Addrs() {
		st.ListenAddrs = append(st.ListenAddrs, a.String())
		st.Bootstrap = append(st.Bootstrap, a.String()+"/p2p/"+id)
	}

	ls, err := m.led.Stats()
	if err != nil {
		return Status{}, err
	}
	st.Storage = StorageInfo{
		Shards:     ls.Shards,
		BytesUsed:  ls.BytesUsed,
		QuotaBytes: m.led.QuotaBytes(),
		Clients:    ls.Clients,
		Owners:     make([]OwnerInfo, 0, len(ls.Owners)),
	}
	for _, o := range ls.Owners {
		st.Storage.Owners = append(st.Storage.Owners, OwnerInfo{
			Owner:      base64.RawStdEncoding.EncodeToString(o.Owner),
			BytesUsed:  o.BytesUsed,
			ShardCount: o.ShardCount,
		})
	}
	// Rebalancing signal (§3.4): capacity/free/load from the configured load
	// source. A load-source error is non-fatal — the node simply reports unknown
	// capacity (0) rather than failing the whole snapshot.
	if m.loadSrc != nil {
		if rep, lerr := m.loadSrc(); lerr == nil {
			st.Storage.CapacityBytes = rep.CapacityBytes
			st.Storage.FreeBytes = rep.FreeBytes()
			st.Storage.Load = rep.Frac()
		} else {
			m.log.Debug("metrics: load source", "err", lerr)
		}
	}

	st.Network = m.networkInfo()
	st.GC = m.gc.Snapshot()
	return st, nil
}

// networkInfo builds the node's current view of the network from the host and,
// when present, the DHT routing table.
func (m *MetricsServer) networkInfo() NetworkInfo {
	ni := NetworkInfo{DHT: m.disc != nil}
	if m.disc != nil {
		ni.RoutingTableSize = m.disc.RoutingTableSize()
	}
	peers := m.h.Network().Peers()
	ni.Connected = len(peers)
	ni.Peers = make([]PeerInfo, 0, len(peers))
	for _, pid := range peers {
		pi := PeerInfo{ID: pid.String(), Direction: "unknown"}
		for _, c := range m.h.Network().ConnsToPeer(pid) {
			pi.Addrs = append(pi.Addrs, c.RemoteMultiaddr().String())
			pi.Direction = connDirection(c.Stat().Direction)
		}
		ni.Peers = append(ni.Peers, pi)
	}
	// Stable order so the output does not churn between scrapes.
	sort.Slice(ni.Peers, func(i, j int) bool { return ni.Peers[i].ID < ni.Peers[j].ID })
	return ni
}

// b2i renders a bool as a Prometheus 0/1 gauge value.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func connDirection(d network.Direction) string {
	switch d {
	case network.DirInbound:
		return "inbound"
	case network.DirOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

// ---- Handlers ----

func (m *MetricsServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (m *MetricsServer) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	// With the DHT on, "ready" means the routing table can route a query. Without
	// it (a single node) the node is ready as soon as it is up.
	ready := m.disc == nil || m.disc.RoutingTableSize() > 0
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "not ready: DHT routing table empty")
		return
	}
	fmt.Fprintln(w, "ready")
}

func (m *MetricsServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := m.snapshot()
	if err != nil {
		m.log.Warn("metrics: status snapshot", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(st); err != nil {
		m.log.Debug("metrics: write status", "err", err)
	}
}

func (m *MetricsServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	st, err := m.snapshot()
	if err != nil {
		m.log.Warn("metrics: metrics snapshot", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	metric := func(name, help, typ string, value float64) {
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
		fmt.Fprintf(w, "%s %s\n", name, strconv.FormatFloat(value, 'f', -1, 64))
	}

	// Build provenance as an info-style metric: a constant 1 carrying the version
	// and build date as labels (the conventional Prometheus build_info pattern).
	fmt.Fprintln(w, "# HELP revika_build_info Build provenance (constant 1; version and build date in labels).")
	fmt.Fprintln(w, "# TYPE revika_build_info gauge")
	fmt.Fprintf(w, "revika_build_info{version=%q,build_date=%q} 1\n", st.Version, st.BuildDate)

	// Versioned stream protocols this node serves, one info-style line (constant 1)
	// per protocol, the protocol ID in a label. revika is pre-release: peers must run
	// matching versions, so operators watch these to confirm the wire versions.
	fmt.Fprintln(w, "# HELP revika_protocol_info Versioned libp2p stream protocol this node serves (constant 1; protocol ID in the protocol label).")
	fmt.Fprintln(w, "# TYPE revika_protocol_info gauge")
	for _, p := range st.Protocols {
		fmt.Fprintf(w, "revika_protocol_info{protocol=%q} 1\n", p)
	}

	// Proof-of-work admission policy this node enforces on writes.
	fmt.Fprintln(w, "# HELP revika_pow_enabled Whether proof-of-work owner-identity admission is enforced on writes (1 = on).")
	fmt.Fprintln(w, "# TYPE revika_pow_enabled gauge")
	fmt.Fprintf(w, "revika_pow_enabled{puzzle=%q} %d\n", "argon2id", b2i(st.PoW.Enabled))
	metric("revika_pow_difficulty_bits", "Required proof-of-work difficulty in leading zero bits (0 = disabled).", "gauge", float64(st.PoW.Difficulty))

	// Maintenance policy this node runs (and advertises to joining peers).
	metric("revika_repair_enabled", "Whether this node runs the availability-repair loop (1 = on).", "gauge", float64(b2i(st.Repair.Enabled)))
	metric("revika_repair_interval_seconds", "Period between repair sweeps in seconds (0 = disabled).", "gauge", st.Repair.Interval.Seconds())
	metric("revika_rebalance_enabled", "Whether this node runs the storage-rebalancing loop (1 = on).", "gauge", float64(b2i(st.Rebalance.Enabled)))
	metric("revika_rebalance_interval_seconds", "Period between rebalance sweeps in seconds (0 = disabled).", "gauge", st.Rebalance.Interval.Seconds())
	metric("revika_rebalance_threshold", "Load-gap dead-band below which the rebalancer moves no shard.", "gauge", st.Rebalance.Threshold)

	// Local abuse controls (Axis A per-subnet flow cap, per-owner write cap, Axis B
	// age-graduated quota). Never inherited from bootstrap — per-node local policy.
	metric("revika_subnet_rate_limit_enabled", "Whether the Axis A identity-agnostic per-subnet flow cap is enforced (1 = on).", "gauge", float64(b2i(st.Defense.SubnetRateLimit.Enabled)))
	metric("revika_subnet_rate_limit_rate", "Axis A sustained per-subnet request rate cap in requests/second (0 when disabled).", "gauge", st.Defense.SubnetRateLimit.Rate)
	metric("revika_subnet_rate_limit_burst", "Axis A per-subnet burst allowance in requests (0 when disabled).", "gauge", st.Defense.SubnetRateLimit.Burst)
	metric("revika_write_rate_limit_enabled", "Whether the per-owner write-verb rate cap is enforced (1 = on).", "gauge", float64(b2i(st.Defense.WriteRateLimit.Enabled)))
	metric("revika_write_rate_limit_rate", "Per-owner write rate cap in writes/second (0 when disabled).", "gauge", st.Defense.WriteRateLimit.Rate)
	metric("revika_write_rate_limit_burst", "Per-owner write burst allowance in writes (0 when disabled).", "gauge", st.Defense.WriteRateLimit.Burst)
	metric("revika_quota_ramp_enabled", "Whether the Axis B age-graduated per-owner quota is in force (1 = on).", "gauge", float64(b2i(st.Defense.QuotaRamp.Enabled)))
	metric("revika_quota_ramp_seconds", "Axis B age at which a new owner reaches its full quota, in seconds (0 = no ramp).", "gauge", st.Defense.QuotaRamp.Ramp.Seconds())
	metric("revika_quota_ramp_initial_fraction", "Axis B fraction of the full quota a brand-new owner may use at age zero.", "gauge", st.Defense.QuotaRamp.InitialFraction)

	// Dialable bootstrap addresses (multiaddr + /p2p/<id>) for `revika-ctl
	// -bootstrap`, one info-style line (constant 1) per address, addr in a label.
	fmt.Fprintln(w, "# HELP revika_bootstrap_info Dialable bootstrap address for revika-ctl -bootstrap (constant 1; address in the addr label).")
	fmt.Fprintln(w, "# TYPE revika_bootstrap_info gauge")
	for _, addr := range st.Bootstrap {
		fmt.Fprintf(w, "revika_bootstrap_info{addr=%q} 1\n", addr)
	}

	metric("revika_uptime_seconds", "Node uptime in seconds.", "gauge", st.UptimeSeconds)
	metric("revika_shards_total", "Distinct shards stored on this node.", "gauge", float64(st.Storage.Shards))
	metric("revika_bytes_used", "Physical bytes stored across all shards.", "gauge", float64(st.Storage.BytesUsed))
	metric("revika_quota_bytes", "Configured per-owner storage quota in bytes (0 = unlimited).", "gauge", float64(st.Storage.QuotaBytes))
	metric("revika_capacity_bytes", "Usable storage budget for load balancing in bytes (0 = unknown).", "gauge", float64(st.Storage.CapacityBytes))
	metric("revika_free_bytes", "Remaining storage budget in bytes (capacity minus used; 0 when unknown/full).", "gauge", float64(st.Storage.FreeBytes))
	metric("revika_load_ratio", "Normalized storage load used/capacity in [0,1] the rebalancer equalizes (0 when capacity unknown).", "gauge", st.Storage.Load)
	metric("revika_clients_total", "Distinct owners (clients) storing shards here.", "gauge", float64(st.Storage.Clients))
	metric("revika_connected_peers", "Currently connected libp2p peers.", "gauge", float64(st.Network.Connected))
	metric("revika_routing_table_size", "Peers in the DHT routing table.", "gauge", float64(st.Network.RoutingTableSize))
	metric("revika_gc_runs_total", "Garbage-collector cycles completed.", "counter", float64(st.GC.Runs))
	metric("revika_gc_shards_reclaimed_total", "Shards reclaimed by the garbage collector.", "counter", float64(st.GC.ShardsReclaimed))
	metric("revika_gc_last_reclaimed", "Shards reclaimed in the most recent GC cycle.", "gauge", float64(st.GC.LastReclaimed))
	metric("revika_gc_last_run_timestamp_seconds", "Unix time of the most recent GC cycle (0 if none yet).", "gauge", float64(st.GC.LastRunUnix))

	// Per-owner accounting, labelled by public key.
	fmt.Fprintln(w, "# HELP revika_owner_bytes_used Bytes charged to an owner (client).")
	fmt.Fprintln(w, "# TYPE revika_owner_bytes_used gauge")
	for _, o := range st.Storage.Owners {
		fmt.Fprintf(w, "revika_owner_bytes_used{owner=%q} %d\n", o.Owner, o.BytesUsed)
	}
	fmt.Fprintln(w, "# HELP revika_owner_shards Shards charged to an owner (client).")
	fmt.Fprintln(w, "# TYPE revika_owner_shards gauge")
	for _, o := range st.Storage.Owners {
		fmt.Fprintf(w, "revika_owner_shards{owner=%q} %d\n", o.Owner, o.ShardCount)
	}
}
