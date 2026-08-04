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
//	GET /status    JSON snapshot: general info, storage accounting, and the
//	               node's view of the network (peer cartography)
//	GET /metrics   Prometheus text-exposition metrics
//
// It reads live state from the host, the ledger, and (optionally) the DHT
// Discovery; it holds no state of its own beyond the start time and version.
//
// Defence controls (security/Defence.md; primitive P27 in security/frameworks.md):
//   AU-6 (Audit Record Review, Analysis, and Reporting) — partial: exposes Prometheus metrics
//        and a JSON status snapshot for external review; no in-node analysis/alerting (Defence.md notes).
type MetricsServer struct {
	h       host.Host
	led     *ledger.Ledger
	disc    *Discovery // optional: nil when the node runs without the DHT
	gc      *GCStats   // optional: nil when GC activity is not tracked
	version string
	started time.Time
	log     *slog.Logger
}

// NewMetricsServer builds a MetricsServer. disc may be nil (no DHT); led must be
// non-nil. version is reported verbatim in /status and /metrics. started is the
// process start time, used to report uptime.
func NewMetricsServer(h host.Host, led *ledger.Ledger, disc *Discovery, version string, started time.Time, log *slog.Logger) *MetricsServer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &MetricsServer{h: h, led: led, disc: disc, version: version, started: started, log: log}
}

// SetGCStats attaches a garbage-collector stats collector so /status and
// /metrics report GC activity. Optional; call before Serve.
func (m *MetricsServer) SetGCStats(gc *GCStats) { m.gc = gc }

// Handler returns the HTTP mux serving the metrics endpoints. Exposed so it can
// be tested directly (via httptest) and mounted by a caller if desired.
func (m *MetricsServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", m.handleHealthz)
	mux.HandleFunc("/readyz", m.handleReadyz)
	mux.HandleFunc("/status", m.handleStatus)
	mux.HandleFunc("/metrics", m.handleMetrics)
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
	PeerID        string      `json:"peer_id"`
	Version       string      `json:"version"`
	UptimeSeconds float64     `json:"uptime_seconds"`
	ListenAddrs   []string    `json:"listen_addrs"`
	Storage       StorageInfo `json:"storage"`
	Network       NetworkInfo `json:"network"`
	GC            GCSnapshot  `json:"gc"`
}

// StorageInfo is the accounting side of /status: what this node holds and for whom.
type StorageInfo struct {
	Shards     int64       `json:"shards"`      // distinct shards stored
	BytesUsed  int64       `json:"bytes_used"`  // physical bytes across all shards
	QuotaBytes int64       `json:"quota_bytes"` // per-owner quota (0 = unlimited)
	Clients    int         `json:"clients"`     // distinct owners storing shards
	Owners     []OwnerInfo `json:"owners"`      // per-owner breakdown, largest first
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
		UptimeSeconds: time.Since(m.started).Seconds(),
	}
	for _, a := range m.h.Addrs() {
		st.ListenAddrs = append(st.ListenAddrs, a.String())
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
	// it (mDNS-only or single node) the node is ready as soon as it is up.
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

	metric("revika_uptime_seconds", "Node uptime in seconds.", "gauge", st.UptimeSeconds)
	metric("revika_shards_total", "Distinct shards stored on this node.", "gauge", float64(st.Storage.Shards))
	metric("revika_bytes_used", "Physical bytes stored across all shards.", "gauge", float64(st.Storage.BytesUsed))
	metric("revika_quota_bytes", "Configured per-owner storage quota in bytes (0 = unlimited).", "gauge", float64(st.Storage.QuotaBytes))
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
