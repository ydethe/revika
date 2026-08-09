package net

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"sort"
	"time"

	manet "github.com/multiformats/go-multiaddr/net"

	"revika/internal/geoip"
)

// adminShardCap bounds how many stored-shard rows the /admin page renders. A node
// can hold far more shards than is useful to dump into one HTML table; beyond this
// the page reports the total and notes the list is truncated.
const adminShardCap = 500

// NodeGeo is one node as the /admin dashboard sees it: identity, connection
// direction, the addresses we hold it on, and — when the IP is global and a
// geolocator is configured — an estimated position. Scope classifies the chosen
// IP so the UI can distinguish a peer with no public position ("local") from one
// we simply could not resolve ("global" but Located false). Self marks the node
// serving the page itself (Direction "self"), so the UI can chip it apart from
// the connected peers.
type NodeGeo struct {
	ID        string         `json:"id"`
	Direction string         `json:"direction"` // "inbound" | "outbound" | "unknown" | "self"
	Self      bool           `json:"self"`      // the node rendering this page
	Addrs     []string       `json:"addrs"`
	IP        string         `json:"ip,omitempty"` // the address chosen for geolocation
	Scope     string         `json:"scope"`        // "global" | "local" | "unknown"
	Located   bool           `json:"located"`      // a position estimate is present
	Location  geoip.Location `json:"location"`     // valid only when Located
}

// placeIP classifies chosen and, for a global IP with a configured locator,
// estimates a position — filling IP/Scope/Located/Location on ng. Shared by the
// per-peer and self views so both place an address identically.
func (m *MetricsServer) placeIP(ctx context.Context, ng *NodeGeo, chosen netip.Addr) {
	if !chosen.IsValid() {
		return
	}
	ng.IP = chosen.String()
	if !geoip.IsGlobal(chosen) {
		ng.Scope = "local"
		return
	}
	ng.Scope = "global"
	if m.geo != nil {
		if loc, ok := m.geo.Locate(ctx, chosen); ok {
			ng.Location = loc
			ng.Located = true
		}
	}
}

// selfGeo builds the dashboard's view of the node serving the page. It places the
// node by its own advertised addresses (m.h.Addrs()), preferring a global address
// so a publicly-reachable node lands on the map alongside its peers.
func (m *MetricsServer) selfGeo(ctx context.Context) NodeGeo {
	ng := NodeGeo{ID: m.h.ID().String(), Direction: "self", Self: true, Scope: "unknown"}
	var chosen netip.Addr
	for _, a := range m.h.Addrs() {
		ng.Addrs = append(ng.Addrs, a.String())
		ip, err := manet.ToIP(a)
		if err != nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !chosen.IsValid() || (!geoip.IsGlobal(chosen) && geoip.IsGlobal(addr)) {
			chosen = addr
		}
	}
	m.placeIP(ctx, &ng, chosen)
	return ng
}

// nodeGeos builds the dashboard's view of currently connected peers. For each
// peer it collects the remote multiaddrs across its connections, picks the best
// IP to place it by (preferring a global address over a private one), classifies
// that IP, and — for a global IP with a configured locator — estimates a
// position. The result is sorted by peer ID for a stable page across reloads.
func (m *MetricsServer) nodeGeos(ctx context.Context) []NodeGeo {
	peers := m.h.Network().Peers()
	out := make([]NodeGeo, 0, len(peers))
	for _, pid := range peers {
		ng := NodeGeo{ID: pid.String(), Direction: "unknown", Scope: "unknown"}
		var chosen netip.Addr
		for _, c := range m.h.Network().ConnsToPeer(pid) {
			rma := c.RemoteMultiaddr()
			ng.Addrs = append(ng.Addrs, rma.String())
			ng.Direction = connDirection(c.Stat().Direction)
			ip, err := manet.ToIP(rma)
			if err != nil {
				continue
			}
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			a = a.Unmap()
			// Prefer a global IP for placement: a peer may be held on both a LAN and
			// a public address, and only the public one geolocates meaningfully.
			if !chosen.IsValid() || (!geoip.IsGlobal(chosen) && geoip.IsGlobal(a)) {
				chosen = a
			}
		}
		m.placeIP(ctx, &ng, chosen)
		out = append(out, ng)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// blocklistView is the /admin panel of the connection blocklist this node
// enforces: the peer IDs and subnets the gater currently refuses (operator-static
// entries unioned with the abuse detector's runtime auto-bans). Configured is
// false when no Blocklister is wired (SetBlocklister not called), so the panel can
// say so rather than render an empty list as "nothing blocked".
type blocklistView struct {
	Configured bool
	Peers      []string // blocked peer IDs, sorted
	Subnets    []string // blocked CIDRs / host routes, sorted
}

// blocklistInfo snapshots the live blocklist for the dashboard. With no
// Blocklister configured it reports Configured false; otherwise it returns the
// current peer IDs and subnets, each sorted for a stable page.
func (m *MetricsServer) blocklistInfo() blocklistView {
	if m.blocklist == nil {
		return blocklistView{}
	}
	peers, subnets := m.blocklist.List()
	bv := blocklistView{Configured: true, Peers: make([]string, 0, len(peers)), Subnets: make([]string, 0, len(subnets))}
	for _, p := range peers {
		bv.Peers = append(bv.Peers, p.String())
	}
	for _, s := range subnets {
		bv.Subnets = append(bv.Subnets, s.String())
	}
	sort.Strings(bv.Peers)
	sort.Strings(bv.Subnets)
	return bv
}

// shardRow is one stored shard as the /admin dashboard shows it, from the ledger
// stripe index: the content-addressed shard ID plus the erasure context (K data /
// M parity, and how many sibling shards the stripe spans).
type shardRow struct {
	ShardID  string
	K, M     int
	Siblings int
}

// shardsView is the /admin panel of the shards this node stores, drawn from the
// ledger stripe index. Total is the full count; Rows is capped at adminShardCap,
// with Truncated set when more shards exist than are shown.
type shardsView struct {
	Total     int
	Truncated bool
	Rows      []shardRow
}

// shardsInfo snapshots the shards this node holds from the ledger stripe index,
// sorted by shard ID for a stable page and capped at adminShardCap rows. A ledger
// error is surfaced to the caller (the dashboard degrades to an empty panel).
func (m *MetricsServer) shardsInfo() (shardsView, error) {
	stripes, err := m.led.Stripes()
	if err != nil {
		return shardsView{}, err
	}
	sort.Slice(stripes, func(i, j int) bool {
		return stripes[i].ShardID.String() < stripes[j].ShardID.String()
	})
	sv := shardsView{Total: len(stripes)}
	for _, st := range stripes {
		if len(sv.Rows) >= adminShardCap {
			sv.Truncated = true
			break
		}
		sv.Rows = append(sv.Rows, shardRow{
			ShardID:  st.ShardID.String(),
			K:        st.K,
			M:        st.M,
			Siblings: len(st.Siblings),
		})
	}
	return sv, nil
}

// adminPage is the data the /admin HTML template renders: the self view (the full
// /status snapshot), the connection blocklist, the stored-shard listing, and the
// connected-peer list plus its map.
type adminPage struct {
	PeerID     string
	Version    string
	Generated  string
	Total      int
	Located    int
	GeoEnabled bool
	Nodes      []NodeGeo
	NodesJSON  template.JS // the same nodes, marshalled, for the map script
	Status     Status      // full /status snapshot, rendered as the self view
	Blocklist  blocklistView
	Shards     shardsView
}

func (m *MetricsServer) handleAdmin(w http.ResponseWriter, r *http.Request) {
	st, err := m.snapshot()
	if err != nil {
		m.log.Warn("metrics: admin snapshot", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	shards, err := m.shardsInfo()
	if err != nil {
		m.log.Warn("metrics: admin shards", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	peers := m.nodeGeos(r.Context())
	// The list and map lead with this node itself, chipped apart from its peers.
	nodes := append([]NodeGeo{m.selfGeo(r.Context())}, peers...)
	located := 0
	for _, n := range nodes {
		if n.Located {
			located++
		}
	}
	data, err := json.Marshal(nodes)
	if err != nil {
		m.log.Warn("metrics: marshal nodes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	page := adminPage{
		PeerID:     m.h.ID().String(),
		Version:    m.version,
		Generated:  time.Now().UTC().Format(time.RFC3339),
		Total:      len(peers), // connected peers, excluding this node
		Located:    located,
		GeoEnabled: m.geo != nil,
		Nodes:      nodes,
		NodesJSON:  template.JS(data),
		Status:     st,
		Blocklist:  m.blocklistInfo(),
		Shards:     shards,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTmpl.Execute(w, page); err != nil {
		// Header is already committed; just record it.
		m.log.Debug("metrics: render admin page", "err", err)
	}
}

// adminFuncs are the render helpers the admin template uses to format the /status
// snapshot: human-readable byte sizes, an uptime duration, a Unix timestamp, and a
// fraction as a percentage.
var adminFuncs = template.FuncMap{
	"bytes":  humanBytes,
	"uptime": func(sec float64) string { return (time.Duration(sec) * time.Second).String() },
	"unix": func(u int64) string {
		if u == 0 {
			return "never"
		}
		return time.Unix(u, 0).UTC().Format(time.RFC3339)
	},
	"pct": func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
}

// humanBytes renders a byte count in binary units (KiB, MiB, …) for the self view.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// adminTmpl renders the /admin operator dashboard. Leaflet and the OSM tiles load
// from public CDNs, so the map needs outbound internet to draw (every other panel
// works offline). Peer-supplied strings reach the DOM only via html/template
// escaping (the tables) or textContent (the map popups), never as raw HTML.
var adminTmpl = template.Must(template.New("admin").Funcs(adminFuncs).Parse(adminHTML))

const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>revika · admin</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
  integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="">
<style>
  :root {
    --bg: #0f1419; --panel: #1a212b; --border: #2b3542; --fg: #e6edf3;
    --muted: #8b98a5; --accent: #4c9aff; --good: #3fb950; --warn: #d29922; --bad: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  header { padding: 16px 20px; border-bottom: 1px solid var(--border); }
  header h1 { margin: 0 0 4px; font-size: 18px; }
  header .meta { color: var(--muted); font-size: 12px; }
  header .meta code { color: var(--fg); }
  .grid {
    display: grid; grid-template-columns: minmax(320px, 5fr) 7fr;
    gap: 16px; padding: 16px 20px; align-items: start;
  }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .section { padding: 0 20px 16px; }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; overflow: hidden;
  }
  .panel > h2 {
    margin: 0; padding: 10px 14px; font-size: 13px; font-weight: 600;
    letter-spacing: .02em; color: var(--muted); text-transform: uppercase;
    border-bottom: 1px solid var(--border); background: rgba(255,255,255,.02);
  }
  #map { height: 460px; width: 100%; background: #0b0f14; }
  .list-wrap { max-height: 460px; overflow: auto; }
  .list-wrap.short { max-height: 300px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { position: sticky; top: 0; background: var(--panel); color: var(--muted); font-weight: 600; z-index: 1; }
  td.mono, .id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .id { word-break: break-all; }
  .addrs { color: var(--muted); font-family: ui-monospace, monospace; font-size: 11px; word-break: break-all; }
  .pill {
    display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px;
    border: 1px solid var(--border); color: var(--muted);
  }
  .pill.global { color: var(--good); border-color: rgba(63,185,80,.4); }
  .pill.local  { color: var(--warn); border-color: rgba(210,153,34,.4); }
  .pill.inbound  { color: var(--accent); border-color: rgba(76,154,255,.4); }
  .pill.outbound { color: var(--good);   border-color: rgba(63,185,80,.4); }
  .pill.self { color: var(--bg); background: var(--accent); border-color: var(--accent); font-weight: 600; }
  .pill.on  { color: var(--good); border-color: rgba(63,185,80,.4); }
  .pill.off { color: var(--muted); }
  .pill.bad { color: var(--bad); border-color: rgba(248,81,73,.4); }
  tr.self-row td { background: rgba(76,154,255,.06); }
  .empty { padding: 28px 14px; color: var(--muted); text-align: center; }
  .note { padding: 8px 14px; color: var(--warn); font-size: 12px; border-bottom: 1px solid var(--border); }
  footer { padding: 8px 20px 20px; color: var(--muted); font-size: 11px; }
  a { color: var(--accent); }
  /* Self view: definition-list of key/value node facts. */
  .kv { margin: 0; padding: 12px 14px; display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; word-break: break-all; }
  .kv dd.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
</style>
</head>
<body>
<header>
  <h1>revika · admin</h1>
  <div class="meta">
    this node <code>{{.PeerID}}</code> · {{.Version}} ·
    {{.Total}} connected ({{.Located}} located) · generated {{.Generated}}
  </div>
</header>

<div class="section">
  <div class="cols">
    <section class="panel" aria-label="Node status">
      <h2>Self · status</h2>
      <dl class="kv">
        <dt>Peer ID</dt><dd class="mono">{{.Status.PeerID}}</dd>
        <dt>Version</dt><dd>{{.Status.Version}}</dd>
        <dt>Build date</dt><dd>{{.Status.BuildDate}}</dd>
        <dt>Uptime</dt><dd>{{uptime .Status.UptimeSeconds}}</dd>
        <dt>DHT</dt><dd>{{if .Status.Network.DHT}}<span class="pill on">on</span>{{else}}<span class="pill off">off</span>{{end}}</dd>
        <dt>Connected peers</dt><dd>{{.Status.Network.Connected}}</dd>
        <dt>Routing table</dt><dd>{{.Status.Network.RoutingTableSize}}</dd>
        <dt>Admission (PoW)</dt><dd>{{if .Status.PoW.Enabled}}<span class="pill on">Argon2id · {{.Status.PoW.Difficulty}} bits</span>{{else}}<span class="pill off">disabled</span>{{end}}</dd>
        <dt>Repair</dt><dd>{{if .Status.Repair.Enabled}}<span class="pill on">every {{.Status.Repair.Interval}}</span>{{else}}<span class="pill off">off</span>{{end}}</dd>
        <dt>Rebalance</dt><dd>{{if .Status.Rebalance.Enabled}}<span class="pill on">every {{.Status.Rebalance.Interval}}</span> · threshold {{printf "%.2f" .Status.Rebalance.Threshold}}{{else}}<span class="pill off">off</span>{{end}}</dd>
        <dt>Protocols</dt><dd class="mono">{{range .Status.Protocols}}{{.}}<br>{{end}}</dd>
        <dt>Listen addrs</dt><dd class="mono">{{range .Status.ListenAddrs}}{{.}}<br>{{end}}</dd>
        <dt>Bootstrap</dt><dd class="mono">{{range .Status.Bootstrap}}{{.}}<br>{{end}}</dd>
      </dl>
    </section>

    <section class="panel" aria-label="Storage and GC">
      <h2>Self · storage &amp; GC</h2>
      <dl class="kv">
        <dt>Shards stored</dt><dd>{{.Status.Storage.Shards}}</dd>
        <dt>Bytes used</dt><dd>{{bytes .Status.Storage.BytesUsed}} <span class="pill">{{.Status.Storage.BytesUsed}} B</span></dd>
        <dt>Per-owner quota</dt><dd>{{if .Status.Storage.QuotaBytes}}{{bytes .Status.Storage.QuotaBytes}}{{else}}<span class="pill off">unlimited</span>{{end}}</dd>
        <dt>Clients (owners)</dt><dd>{{.Status.Storage.Clients}}</dd>
        <dt>Capacity</dt><dd>{{if .Status.Storage.CapacityBytes}}{{bytes .Status.Storage.CapacityBytes}}{{else}}<span class="pill off">unknown</span>{{end}}</dd>
        <dt>Free</dt><dd>{{if .Status.Storage.CapacityBytes}}{{bytes .Status.Storage.FreeBytes}}{{else}}<span class="pill off">unknown</span>{{end}}</dd>
        <dt>Load</dt><dd>{{if .Status.Storage.CapacityBytes}}{{pct .Status.Storage.Load}}{{else}}<span class="pill off">unknown</span>{{end}}</dd>
        <dt>GC cycles</dt><dd>{{.Status.GC.Runs}}</dd>
        <dt>Shards reclaimed</dt><dd>{{.Status.GC.ShardsReclaimed}} total · {{.Status.GC.LastReclaimed}} last</dd>
        <dt>Last GC run</dt><dd>{{unix .Status.GC.LastRunUnix}}</dd>
      </dl>
      {{if .Status.Storage.Owners}}
      <div class="list-wrap short">
        <table>
          <thead><tr><th>Owner (pubkey)</th><th>Bytes</th><th>Shards</th></tr></thead>
          <tbody>
            {{range .Status.Storage.Owners}}
            <tr><td class="id">{{.Owner}}</td><td>{{bytes .BytesUsed}}</td><td>{{.ShardCount}}</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
      {{end}}
    </section>
  </div>
</div>

<div class="section">
  <div class="cols">
    <section class="panel" aria-label="Blocklist">
      <h2>Blocklist{{if .Blocklist.Configured}} ({{len .Blocklist.Peers}} peers · {{len .Blocklist.Subnets}} subnets){{end}}</h2>
      {{if not .Blocklist.Configured}}
        <div class="empty">No blocklist configured on this node.</div>
      {{else if and (not .Blocklist.Peers) (not .Blocklist.Subnets)}}
        <div class="empty">Blocklist is empty — no peers or subnets refused.</div>
      {{else}}
        <div class="list-wrap short">
          <table>
            <thead><tr><th>Kind</th><th>Entry</th></tr></thead>
            <tbody>
              {{range .Blocklist.Peers}}<tr><td><span class="pill bad">peer</span></td><td class="id">{{.}}</td></tr>{{end}}
              {{range .Blocklist.Subnets}}<tr><td><span class="pill bad">subnet</span></td><td class="mono">{{.}}</td></tr>{{end}}
            </tbody>
          </table>
        </div>
      {{end}}
    </section>

    <section class="panel" aria-label="Stored shards">
      <h2>Stored shards ({{.Shards.Total}})</h2>
      {{if .Shards.Truncated}}<div class="note">Showing the first {{len .Shards.Rows}} of {{.Shards.Total}} shards.</div>{{end}}
      {{if not .Shards.Rows}}
        <div class="empty">No shards with stripe context stored on this node.</div>
      {{else}}
        <div class="list-wrap short">
          <table>
            <thead><tr><th>Shard ID (content hash)</th><th>k</th><th>m</th><th>Siblings</th></tr></thead>
            <tbody>
              {{range .Shards.Rows}}
              <tr><td class="id">{{.ShardID}}</td><td>{{.K}}</td><td>{{.M}}</td><td>{{.Siblings}}</td></tr>
              {{end}}
            </tbody>
          </table>
        </div>
      {{end}}
    </section>
  </div>
</div>

<div class="grid">
  <section class="panel" aria-label="Node list">
    <h2>Nodes ({{len .Nodes}})</h2>
    {{if not .GeoEnabled}}<div class="note">Geolocation disabled — start revika-node with <code>-geoip=ip-api</code> to place nodes on the map.</div>{{end}}
    <div class="list-wrap">
      {{if not .Total}}<div class="empty">No peers currently connected.</div>{{end}}
      <table>
        <thead><tr><th>Peer</th><th>Dir</th><th>IP</th><th>Location</th><th>Address</th></tr></thead>
        <tbody>
          {{range .Nodes}}
          <tr{{if .Self}} class="self-row"{{end}}>
            <td class="id">{{.ID}}{{if .Self}} <span class="pill self">this node</span>{{end}}</td>
            <td><span class="pill {{.Direction}}">{{.Direction}}</span></td>
            <td class="mono">{{if .IP}}{{.IP}} <span class="pill {{.Scope}}">{{.Scope}}</span>{{else}}<span class="pill">n/a</span>{{end}}</td>
            <td>{{if .Located}}{{with .Location}}{{if .City}}{{.City}}, {{end}}{{.Country}} <span class="pill">{{printf "%.2f" .Lat}}, {{printf "%.2f" .Lon}}</span>{{end}}{{else}}<span class="pill">unknown</span>{{end}}</td>
            <td class="addrs">{{range .Addrs}}{{.}}<br>{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
  </section>

  <section class="panel" aria-label="Node map">
    <h2>Geographic map</h2>
    <div id="map"></div>
  </section>
</div>

<footer>Positions are coarse IP-based estimates. Map tiles © OpenStreetMap contributors.</footer>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
  integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<script>
  var REVIKA_NODES = {{.NodesJSON}};
  (function () {
    var el = document.getElementById('map');
    if (typeof L === 'undefined') { el.textContent = 'Map library failed to load (needs internet).'; return; }
    var map = L.map(el, { worldCopyJump: true }).setView([20, 0], 2);
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18, attribution: '© OpenStreetMap contributors'
    }).addTo(map);

    var located = (REVIKA_NODES || []).filter(function (n) { return n.located; });
    var bounds = [];
    located.forEach(function (n) {
      var lat = n.location.lat, lon = n.location.lon;
      // This node draws as a filled accent circle to stand apart from the peer pins.
      var m = n.self
        ? L.circleMarker([lat, lon], { radius: 8, color: '#4c9aff', fillColor: '#4c9aff', fillOpacity: .9, weight: 2 }).addTo(map)
        : L.marker([lat, lon]).addTo(map);
      // Build the popup as DOM so peer-supplied text can never inject HTML.
      var box = document.createElement('div');
      var loc = n.location || {};
      var place = [loc.city, loc.country].filter(Boolean).join(', ');
      var b = document.createElement('div'); b.style.fontWeight = '600';
      b.textContent = (n.self ? 'This node — ' : '') + (place || 'Unknown place');
      var id = document.createElement('div'); id.style.fontFamily = 'monospace'; id.style.fontSize = '11px';
      id.textContent = n.id;
      var ip = document.createElement('div'); ip.style.color = '#8b98a5'; ip.style.fontSize = '11px';
      ip.textContent = (n.ip || '') + ' · ' + n.direction;
      box.appendChild(b); box.appendChild(id); box.appendChild(ip);
      m.bindPopup(box);
      bounds.push([lat, lon]);
    });
    if (bounds.length === 1) { map.setView(bounds[0], 5); }
    else if (bounds.length > 1) { map.fitBounds(bounds, { padding: [40, 40] }); }
  })();
</script>
</body>
</html>`
