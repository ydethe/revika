package net

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"revika/internal/ledger"
	"revika/internal/store"
)

// newMetricsFixture builds a MetricsServer backed by a real (loopback) host and
// a temp-file ledger, plus an httptest server for its handler.
func newMetricsFixture(t *testing.T) (*MetricsServer, *ledger.Ledger, *httptest.Server) {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { h.Close() })

	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })

	ms := NewMetricsServer(h, led, nil /* no DHT */, "test-1.2.3", "2026-08-05T12:00:00Z", time.Now(), nil)
	ms.SetPoW(12)
	ms.SetProtocols(NewServer(store.NewMemStore(), nil).Protocols())
	ts := httptest.NewServer(ms.Handler())
	t.Cleanup(ts.Close)
	return ms, led, ts
}

func getBody(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestMetricsHealthAndReady(t *testing.T) {
	_, _, ts := newMetricsFixture(t)

	if code, body := getBody(t, ts.URL+"/healthz"); code != http.StatusOK || !strings.Contains(body, "ok") {
		t.Fatalf("/healthz = %d %q", code, body)
	}
	// No DHT configured => always ready.
	if code, body := getBody(t, ts.URL+"/readyz"); code != http.StatusOK || !strings.Contains(body, "ready") {
		t.Fatalf("/readyz = %d %q", code, body)
	}
}

func TestMetricsStatusReflectsLedger(t *testing.T) {
	_, led, ts := newMetricsFixture(t)

	now := time.Now()
	var s1, s2 store.ShardID
	s1[0], s2[0] = 1, 2
	owner := []byte("alice-pubkey-000000000000000000")
	if _, err := led.AddOwner(s1, owner, 100, now); err != nil {
		t.Fatalf("AddOwner s1: %v", err)
	}
	if _, err := led.AddOwner(s2, owner, 200, now); err != nil {
		t.Fatalf("AddOwner s2: %v", err)
	}

	code, body := getBody(t, ts.URL+"/status")
	if code != http.StatusOK {
		t.Fatalf("/status = %d", code)
	}
	var st Status
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode status: %v (body=%s)", err, body)
	}
	if st.Version != "test-1.2.3" {
		t.Errorf("version = %q, want test-1.2.3", st.Version)
	}
	if st.BuildDate != "2026-08-05T12:00:00Z" {
		t.Errorf("build_date = %q, want 2026-08-05T12:00:00Z", st.BuildDate)
	}
	if !st.PoW.Enabled || st.PoW.Difficulty != 12 {
		t.Errorf("pow = %+v, want enabled at difficulty 12", st.PoW)
	}
	// The served stream protocols are advertised (sorted), so an operator can
	// confirm the wire versions from /status.
	wantProtos := []string{
		string(BalanceProtocol), string(ParamsProtocol),
		string(ProbeProtocol), string(ShardProtocol),
	}
	sort.Strings(wantProtos)
	if !slices.Equal(st.Protocols, wantProtos) {
		t.Errorf("protocols = %v, want %v", st.Protocols, wantProtos)
	}
	if st.PeerID == "" {
		t.Error("empty peer_id")
	}
	// Every listen address must have a matching bootstrap string ending in the
	// node's own /p2p/<peer-id>, ready to paste into `revika-ctl -bootstrap`.
	if len(st.Bootstrap) != len(st.ListenAddrs) || len(st.Bootstrap) == 0 {
		t.Fatalf("bootstrap = %v, want one per listen addr (%v)", st.Bootstrap, st.ListenAddrs)
	}
	for i, b := range st.Bootstrap {
		want := st.ListenAddrs[i] + "/p2p/" + st.PeerID
		if b != want {
			t.Errorf("bootstrap[%d] = %q, want %q", i, b, want)
		}
	}
	if st.Storage.Shards != 2 || st.Storage.BytesUsed != 300 || st.Storage.Clients != 1 {
		t.Errorf("storage = %+v, want 2 shards / 300 bytes / 1 client", st.Storage)
	}
	if st.Network.DHT {
		t.Error("network.dht = true, want false (no DHT configured)")
	}
	if len(st.Storage.Owners) != 1 || st.Storage.Owners[0].ShardCount != 2 {
		t.Errorf("owners = %+v, want one owner with 2 shards", st.Storage.Owners)
	}
}

func TestMetricsPrometheus(t *testing.T) {
	_, led, ts := newMetricsFixture(t)
	if _, err := led.AddOwner(store.ShardID{9}, []byte("carol-key-0000000000000000000000"), 512, time.Now()); err != nil {
		t.Fatalf("AddOwner: %v", err)
	}

	code, body := getBody(t, ts.URL+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d", code)
	}
	for _, want := range []string{
		"# TYPE revika_bytes_used gauge",
		"revika_bytes_used 512",
		"revika_shards_total 1",
		"revika_clients_total 1",
		"revika_quota_bytes 0",
		"# TYPE revika_gc_runs_total counter",
		"revika_gc_runs_total 0",
		"revika_owner_bytes_used{owner=",
		`revika_build_info{version="test-1.2.3",build_date="2026-08-05T12:00:00Z"} 1`,
		"# TYPE revika_protocol_info gauge",
		`revika_protocol_info{protocol="` + string(ShardProtocol) + `"} 1`,
		`revika_protocol_info{protocol="` + string(ProbeProtocol) + `"} 1`,
		`revika_pow_enabled{puzzle="argon2id"} 1`,
		"revika_pow_difficulty_bits 12",
		"# TYPE revika_bootstrap_info gauge",
		"revika_bootstrap_info{addr=",
		"/p2p/",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, body)
		}
	}
}

func TestMetricsReportsDefenses(t *testing.T) {
	ms, _, ts := newMetricsFixture(t)
	// Mirror the on-by-default wiring cmd/revika-node assembles: Axis A enabled,
	// per-owner write cap enabled, Axis B enabled.
	ms.SetDefenses(DefenseInfo{
		SubnetRateLimit: SubnetLimitInfo{Enabled: true, Rate: 1000, Burst: 4000, Prefix4: 24, Prefix6: 56},
		WriteRateLimit:  WriteLimitInfo{Enabled: true, Rate: 50, Burst: 100},
		QuotaRamp:       QuotaRampInfo{Enabled: true, Ramp: 7 * 24 * time.Hour, InitialFraction: 0.05},
	})

	// /status carries the structured defense block.
	code, body := getBody(t, ts.URL+"/status")
	if code != http.StatusOK {
		t.Fatalf("/status = %d", code)
	}
	var st Status
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode status: %v (body=%s)", err, body)
	}
	d := st.Defense
	if !d.SubnetRateLimit.Enabled || d.SubnetRateLimit.Rate != 1000 || d.SubnetRateLimit.Burst != 4000 ||
		d.SubnetRateLimit.Prefix4 != 24 || d.SubnetRateLimit.Prefix6 != 56 {
		t.Errorf("subnet_rate_limit = %+v, want enabled 1000/s burst 4000 /24 /56", d.SubnetRateLimit)
	}
	if !d.WriteRateLimit.Enabled || d.WriteRateLimit.Rate != 50 || d.WriteRateLimit.Burst != 100 {
		t.Errorf("write_rate_limit = %+v, want enabled 50/s burst 100", d.WriteRateLimit)
	}
	if !d.QuotaRamp.Enabled || d.QuotaRamp.Ramp != 7*24*time.Hour || d.QuotaRamp.InitialFraction != 0.05 {
		t.Errorf("quota_ramp = %+v, want enabled ramp 168h initial 0.05", d.QuotaRamp)
	}

	// /metrics exposes the same as gauges.
	code, body = getBody(t, ts.URL+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d", code)
	}
	for _, want := range []string{
		"# TYPE revika_subnet_rate_limit_enabled gauge",
		"revika_subnet_rate_limit_enabled 1",
		"revika_subnet_rate_limit_rate 1000",
		"revika_subnet_rate_limit_burst 4000",
		"revika_write_rate_limit_enabled 1",
		"revika_write_rate_limit_rate 50",
		"revika_write_rate_limit_burst 100",
		"revika_quota_ramp_enabled 1",
		"revika_quota_ramp_seconds 604800",
		"revika_quota_ramp_initial_fraction 0.05",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, body)
		}
	}
}

func TestMetricsGCAndQuota(t *testing.T) {
	// Build a fixture with a non-zero quota and a GC stats collector wired in.
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), ledger.Options{QuotaBytes: 4096})
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })

	gc := NewGCStats()
	gc.Record(3, 1, 2, time.Unix(1_700_000_000, 0))
	gc.Record(2, 0, 0, time.Unix(1_700_000_060, 0))

	ms := NewMetricsServer(h, led, nil, "v", "unknown", time.Now(), nil)
	ms.SetGCStats(gc)
	ts := httptest.NewServer(ms.Handler())
	t.Cleanup(ts.Close)

	code, body := getBody(t, ts.URL+"/status")
	if code != http.StatusOK {
		t.Fatalf("/status = %d", code)
	}
	var st Status
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.Storage.QuotaBytes != 4096 {
		t.Errorf("quota_bytes = %d, want 4096", st.Storage.QuotaBytes)
	}
	// Two cycles; 3+2 = 5 shards reclaimed total; last cycle reclaimed 2.
	if st.GC.Runs != 2 || st.GC.ShardsReclaimed != 5 || st.GC.LastReclaimed != 2 {
		t.Errorf("gc = %+v, want runs=2 reclaimed=5 last=2", st.GC)
	}
	if st.GC.LastRunUnix != 1_700_000_060 {
		t.Errorf("gc.last_run_unix = %d, want 1700000060", st.GC.LastRunUnix)
	}
}
