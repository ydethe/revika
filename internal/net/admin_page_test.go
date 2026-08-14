package net

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/geoip"
	"revika/internal/store"
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

type fakeSelfLocator struct{ fakeLocator }

func (f fakeSelfLocator) LocateSelf(_ context.Context) (geoip.Location, bool) {
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

func TestAdminPageNoPeers(t *testing.T) {
	// A fresh fixture host has no connected peers and no geolocator configured.
	_, _, ts := newMetricsFixture(t)
	code, body := getBody(t, ts.URL+"/admin")
	if code != 200 {
		t.Fatalf("/admin = %d, want 200", code)
	}
	for _, want := range []string{
		"revika · admin",               // page title/header
		"Self · status",                // the self view (full /status snapshot)
		"No peers currently connected", // empty-list state
		"-geoip=ip-api",                // the geolocation-disabled hint
		`id="map"`,                     // the map panel is present
		"Self · defenses",              // the local abuse-control panel (Axis A/B + write cap)
		"Ledger browser",               // the filterable ledger panel
		"The ledger holds no shards",   // its empty state
		"Blocklist",                    // the blocklist panel
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/admin body missing %q", want)
		}
	}
}

// TestAdminPageSelf confirms the node serving the page lists itself, chipped
// apart from its peers, even when no peer is connected.
func TestAdminPageSelf(t *testing.T) {
	ms, _, ts := newMetricsFixture(t)
	ms.SetGeolocator(fakeSelfLocator{fakeLocator{loc: geoip.Location{Lat: 1, Lon: 2, City: "Self City"}}})
	code, body := getBody(t, ts.URL+"/admin")
	if code != 200 {
		t.Fatalf("/admin = %d, want 200", code)
	}
	if !strings.Contains(body, ms.h.ID().String()) {
		t.Errorf("/admin did not list this node's own peer ID %s", ms.h.ID())
	}
	if !strings.Contains(body, `pill self">this node`) {
		t.Errorf("/admin missing the \"this node\" chip distinguishing the serving node")
	}
	// The self row's JSON must carry the self flag so the map can mark it too.
	if !strings.Contains(body, `"self":true`) {
		t.Errorf("/admin map JSON missing the self flag")
	}
	if !strings.Contains(body, `"located":true`) {
		t.Errorf("/admin map JSON missing the self location")
	}
	// The self view renders the /status snapshot: the PoW admission line must show
	// the fixture's difficulty (12) and the served protocols must appear.
	if !strings.Contains(body, "Argon2id") {
		t.Errorf("/admin self view missing the proof-of-work admission line")
	}
}

func TestAdminPageContentType(t *testing.T) {
	_, _, ts := newMetricsFixture(t)
	resp, err := ts.Client().Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("/admin Content-Type = %q, want text/html", ct)
	}
}

// TestAdminPageLedgerBrowser confirms a shard shows up in the ledger-browser panel
// with its erasure context, and that the shard-ID prefix and owner-key filters both
// narrow the view server-side.
func TestAdminPageLedgerBrowser(t *testing.T) {
	_, led, ts := newMetricsFixture(t)
	now := time.Now()
	var id, sib, other store.ShardID
	id[0], sib[0], other[0] = 0xab, 0xcd, 0x77
	owner := []byte("owner-pubkey-00000000000000000000")
	otherOwner := []byte("other-pubkey-00000000000000000000")
	if _, err := led.AddOwner(id, owner, 100, now); err != nil {
		t.Fatalf("AddOwner id: %v", err)
	}
	if err := led.PutStripe(id, 4, 2, []store.ShardID{id, sib}, []byte("grant")); err != nil {
		t.Fatalf("PutStripe: %v", err)
	}
	if _, err := led.AddOwner(other, otherOwner, 200, now); err != nil {
		t.Fatalf("AddOwner other: %v", err)
	}

	// Unfiltered: both shards and the erasure chip for the striped one appear.
	code, body := getBody(t, ts.URL+"/admin")
	if code != 200 {
		t.Fatalf("/admin = %d, want 200", code)
	}
	if !strings.Contains(body, id.String()) || !strings.Contains(body, other.String()) {
		t.Errorf("/admin ledger browser missing a shard ID (want both %s and %s)", id, other)
	}
	if !strings.Contains(body, "k=4 · m=2") {
		t.Errorf("/admin ledger browser missing the erasure context chip")
	}

	// Filter by the striped shard's hex prefix: it stays, the other drops.
	_, body = getBody(t, ts.URL+"/admin?lshard=ab")
	if !strings.Contains(body, id.String()) {
		t.Errorf("shard-prefix filter dropped the matching shard %s", id)
	}
	if strings.Contains(body, other.String()) {
		t.Errorf("shard-prefix filter kept the non-matching shard %s", other)
	}

	// Filter by owner key (base64, as the storage panel renders it).
	ownerB64 := base64.RawStdEncoding.EncodeToString(owner)
	_, body = getBody(t, ts.URL+"/admin?lowner="+url.QueryEscape(ownerB64))
	if !strings.Contains(body, id.String()) {
		t.Errorf("owner filter dropped the owner's shard %s", id)
	}
	if strings.Contains(body, other.String()) {
		t.Errorf("owner filter kept a shard owned by someone else %s", other)
	}

	// A bad owner filter is reported, not fatal.
	code, body = getBody(t, ts.URL+"/admin?lowner=not!base64!")
	if code != 200 {
		t.Fatalf("/admin with bad owner filter = %d, want 200", code)
	}
	if !strings.Contains(body, "not valid base64") {
		t.Errorf("/admin did not report an undecodable owner filter")
	}
}

// TestAdminPageBlocklist confirms a configured blocklist surfaces its banned peer
// on the page, and that with no Blocklister the panel says so.
func TestAdminPageBlocklist(t *testing.T) {
	ms, _, ts := newMetricsFixture(t)

	// No Blocklister wired yet: the panel reports none configured.
	_, body := getBody(t, ts.URL+"/admin")
	if !strings.Contains(body, "No blocklist configured") {
		t.Errorf("/admin should report no blocklist before one is set")
	}

	// Mint a real peer ID to ban (hand-written IDs may not decode across libp2p
	// versions) and seed the blocklist with both a peer and a subnet.
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("mint peer: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	banned := h.ID()

	_, sub, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	bl, err := NewBlocklister(nil, []*net.IPNet{sub}, "", nil)
	if err != nil {
		t.Fatalf("new blocklister: %v", err)
	}
	bl.Block(banned, "test")
	ms.SetBlocklister(bl)

	_, body = getBody(t, ts.URL+"/admin")
	if !strings.Contains(body, banned.String()) {
		t.Errorf("/admin blocklist panel missing banned peer %s", banned)
	}
	if !strings.Contains(body, "203.0.113.0/24") {
		t.Errorf("/admin blocklist panel missing banned subnet")
	}
}

// TestAdminPageLivePeer exercises the real gathering path: a second host connects
// to the fixture over loopback and must appear in the list. The connection is a
// non-global (127.0.0.1) address, so the peer is classified "local" and never
// located, even though a geolocator is configured.
func TestAdminPageLivePeer(t *testing.T) {
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
		_, body = getBody(t, ts.URL+"/admin")
		if strings.Contains(body, peer2.ID().String()) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(body, peer2.ID().String()) {
		t.Fatalf("/admin never listed connected peer %s", peer2.ID())
	}
	if !strings.Contains(body, "local</span>") {
		t.Errorf("expected the loopback peer to be marked local (non-global, so not located)")
	}
}

// TestAdminTemplateRender drives the template directly with a synthetic located
// node and a local one, since two loopback hosts only ever connect over
// non-global (127.0.0.1) addresses and so never produce a located marker.
func TestAdminTemplateRender(t *testing.T) {
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
	page := adminPage{
		PeerID:     "12D3KooWSelf",
		Version:    "test-1.0.0",
		Generated:  "2026-08-08T00:00:00Z",
		Total:      2,
		Located:    1,
		GeoEnabled: true,
		Nodes:      []NodeGeo{located, local},
		NodesJSON:  mustNodesJSON(t, []NodeGeo{located, local}),
		Status: Status{
			PeerID:    "12D3KooWSelf",
			Version:   "test-1.0.0",
			Protocols: []string{"/revika/shard/1.2.0"},
			Storage:   StorageInfo{Shards: 3, BytesUsed: 4096, QuotaBytes: 1 << 20},
			Defense: DefenseInfo{
				SubnetRateLimit: SubnetLimitInfo{Enabled: true, Rate: 1000, Burst: 4000, Prefix4: 24, Prefix6: 56},
				WriteRateLimit:  WriteLimitInfo{Enabled: false},
				QuotaRamp:       QuotaRampInfo{Enabled: true, Ramp: 7 * 24 * time.Hour, InitialFraction: 0.05},
			},
		},
	}
	var buf bytes.Buffer
	if err := adminTmpl.Execute(&buf, page); err != nil {
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
		"self-map-icon",       // the map has a dedicated self-node icon
		"/revika/shard/1.2.0", // self view lists the served protocol
		"4.0 KiB",             // human-readable bytes-used in the self view
		"Self · defenses",     // the local abuse-control panel
		"1000/s · burst 4000", // Axis A subnet cap rendered
		"/24 v4 · /56 v6",     // Axis A subnet prefixes
		"5.0% → full over",    // Axis B quota ramp rendered
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

// TestAdminTemplateEscaping confirms a hostile peer-supplied string cannot inject
// markup: html/template must escape it in the table cell.
func TestAdminTemplateEscaping(t *testing.T) {
	evil := NodeGeo{
		ID:        "<script>alert(1)</script>",
		Direction: "unknown",
		Addrs:     []string{"/ip4/198.51.100.9/tcp/1"},
		IP:        "198.51.100.9",
		Scope:     "global",
	}
	page := adminPage{Total: 1, Nodes: []NodeGeo{evil}, NodesJSON: mustNodesJSON(t, []NodeGeo{evil})}
	var buf bytes.Buffer
	if err := adminTmpl.Execute(&buf, page); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Fatal("peer-supplied ID was rendered as raw HTML (XSS): escaping failed")
	}
	if !strings.Contains(buf.String(), "&lt;script&gt;") {
		t.Fatal("expected the peer ID to be HTML-escaped in the table")
	}
}
