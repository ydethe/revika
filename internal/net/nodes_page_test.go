package net

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/geoip"
)

// fakeLocator is a deterministic Locator for tests: a fixed position for any
// global IP, not-located for the rest (mirroring IsGlobal).
type fakeLocator struct{ loc geoip.Location }

func (f fakeLocator) Locate(_ context.Context, ip netip.Addr) (geoip.Location, bool) {
	if !geoip.IsGlobal(ip) {
		return geoip.Location{}, false
	}
	return f.loc, true
}

// mustNodesJSON marshals nodes the way the handler does, for template tests.
func mustNodesJSON(t *testing.T, nodes []NodeGeo) template.JS {
	t.Helper()
	b, err := json.Marshal(nodes)
	if err != nil {
		t.Fatalf("marshal nodes: %v", err)
	}
	return template.JS(b)
}

func TestNodesPageNoPeers(t *testing.T) {
	// A fresh fixture host has no connected peers and no geolocator configured.
	_, _, ts := newMetricsFixture(t)
	code, body := getBody(t, ts.URL+"/nodes")
	if code != 200 {
		t.Fatalf("/nodes = %d, want 200", code)
	}
	for _, want := range []string{
		"connected nodes",              // page title/header
		"No peers currently connected", // empty-list state
		"-geoip=ip-api",                // the geolocation-disabled hint
		`id="map"`,                     // the map panel is present
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/nodes body missing %q", want)
		}
	}
}

func TestNodesPageContentType(t *testing.T) {
	_, _, ts := newMetricsFixture(t)
	resp, err := ts.Client().Get(ts.URL + "/nodes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("/nodes Content-Type = %q, want text/html", ct)
	}
}

// TestNodesPageLivePeer exercises the real gathering path: a second host connects
// to the fixture over loopback and must appear in the list. The connection is a
// non-global (127.0.0.1) address, so the peer is classified "local" and never
// located, even though a geolocator is configured.
func TestNodesPageLivePeer(t *testing.T) {
	ctx := context.Background()
	ms, _, ts := newMetricsFixture(t)
	ms.SetGeolocator(fakeLocator{loc: geoip.Location{Lat: 1, Lon: 2, City: "Nowhere"}})

	peer2, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("new peer host: %v", err)
	}
	t.Cleanup(func() { peer2.Close() })
	if err := Connect(ctx, peer2, peer.AddrInfo{ID: ms.h.ID(), Addrs: ms.h.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// The inbound connection registers on the fixture host essentially at once, but
	// poll briefly so the test is not sensitive to scheduling.
	var body string
	for range 40 {
		_, body = getBody(t, ts.URL+"/nodes")
		if strings.Contains(body, peer2.ID().String()) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(body, peer2.ID().String()) {
		t.Fatalf("/nodes never listed connected peer %s", peer2.ID())
	}
	if !strings.Contains(body, "local</span>") {
		t.Errorf("expected the loopback peer to be marked local (non-global, so not located)")
	}
}

// TestNodesTemplateRender drives the template directly with a synthetic located
// node and a local one, since two loopback hosts only ever connect over
// non-global (127.0.0.1) addresses and so never produce a located marker.
func TestNodesTemplateRender(t *testing.T) {
	located := NodeGeo{
		ID:        "12D3KooWLocatedPeerExample",
		Direction: "outbound",
		Addrs:     []string{"/ip4/203.0.113.7/tcp/4001"},
		IP:        "203.0.113.7",
		Scope:     "global",
		Located:   true,
		Location:  geoip.Location{Lat: 48.85, Lon: 2.35, City: "Paris", Country: "France", CountryCode: "FR"},
	}
	local := NodeGeo{
		ID:        "12D3KooWLocalPeerExample",
		Direction: "inbound",
		Addrs:     []string{"/ip4/192.168.1.4/tcp/4001"},
		IP:        "192.168.1.4",
		Scope:     "local",
	}
	page := nodesPage{
		PeerID:     "12D3KooWSelf",
		Version:    "test-1.0.0",
		Generated:  "2026-08-08T00:00:00Z",
		Total:      2,
		Located:    1,
		GeoEnabled: true,
		Nodes:      []NodeGeo{located, local},
		NodesJSON:  mustNodesJSON(t, []NodeGeo{located, local}),
	}
	var buf bytes.Buffer
	if err := nodesTmpl.Execute(&buf, page); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Paris, France",       // located node's place in the table
		"48.85, 2.35",         // its coordinates
		"12D3KooWLocatedPeer", // peer IDs rendered
		"12D3KooWLocalPeer",
		"203.0.113.7",
		`"located":true`, // the map JSON carries the located flag
		`"lat":48.85`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	// GeoEnabled true => no "enable geolocation" note.
	if strings.Contains(out, "-geoip=ip-api") {
		t.Error("geolocation-enabled page should not show the enable hint")
	}
}

// TestNodesTemplateEscaping confirms a hostile peer-supplied string cannot inject
// markup: html/template must escape it in the table cell.
func TestNodesTemplateEscaping(t *testing.T) {
	evil := NodeGeo{
		ID:        "<script>alert(1)</script>",
		Direction: "unknown",
		Addrs:     []string{"/ip4/198.51.100.9/tcp/1"},
		IP:        "198.51.100.9",
		Scope:     "global",
	}
	page := nodesPage{Total: 1, Nodes: []NodeGeo{evil}, NodesJSON: mustNodesJSON(t, []NodeGeo{evil})}
	var buf bytes.Buffer
	if err := nodesTmpl.Execute(&buf, page); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Fatal("peer-supplied ID was rendered as raw HTML (XSS): escaping failed")
	}
	if !strings.Contains(buf.String(), "&lt;script&gt;") {
		t.Fatal("expected the peer ID to be HTML-escaped in the table")
	}
}
