package net

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

	ms := NewMetricsServer(h, led, nil /* no DHT */, "test-1.2.3", time.Now(), nil)
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
	if st.PeerID == "" {
		t.Error("empty peer_id")
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

	ms := NewMetricsServer(h, led, nil, "v", time.Now(), nil)
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
