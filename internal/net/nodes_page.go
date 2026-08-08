package net

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/netip"
	"sort"
	"time"

	manet "github.com/multiformats/go-multiaddr/net"

	"revika/internal/geoip"
)

// NodeGeo is one node as the /nodes dashboard sees it: identity, connection
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

// nodesPage is the data the /nodes HTML template renders.
type nodesPage struct {
	PeerID     string
	Version    string
	Generated  string
	Total      int
	Located    int
	GeoEnabled bool
	Nodes      []NodeGeo
	NodesJSON  template.JS // the same nodes, marshalled, for the map script
}

func (m *MetricsServer) handleNodes(w http.ResponseWriter, r *http.Request) {
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
	page := nodesPage{
		PeerID:     m.h.ID().String(),
		Version:    m.version,
		Generated:  time.Now().UTC().Format(time.RFC3339),
		Total:      len(peers), // connected peers, excluding this node
		Located:    located,
		GeoEnabled: m.geo != nil,
		Nodes:      nodes,
		NodesJSON:  template.JS(data),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := nodesTmpl.Execute(w, page); err != nil {
		// Header is already committed; just record it.
		m.log.Debug("metrics: render nodes page", "err", err)
	}
}

// nodesTmpl renders the /nodes dashboard: two panels — a detailed peer list and
// a Leaflet/OpenStreetMap map with a marker per located peer. Leaflet and the OSM
// tiles load from public CDNs, so the page needs outbound internet to draw the
// map (the list works offline). Peer-supplied strings reach the DOM only via
// html/template escaping (the table) or textContent (the map popups), never as
// raw HTML.
var nodesTmpl = template.Must(template.New("nodes").Parse(nodesHTML))

const nodesHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>revika · connected nodes</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
  integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="">
<style>
  :root {
    --bg: #0f1419; --panel: #1a212b; --border: #2b3542; --fg: #e6edf3;
    --muted: #8b98a5; --accent: #4c9aff; --good: #3fb950; --warn: #d29922;
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
  tr.self-row td { background: rgba(76,154,255,.06); }
  .empty { padding: 28px 14px; color: var(--muted); text-align: center; }
  .note { padding: 8px 14px; color: var(--warn); font-size: 12px; border-bottom: 1px solid var(--border); }
  footer { padding: 8px 20px 20px; color: var(--muted); font-size: 11px; }
  a { color: var(--accent); }
</style>
</head>
<body>
<header>
  <h1>revika · connected nodes</h1>
  <div class="meta">
    this node <code>{{.PeerID}}</code> · {{.Version}} ·
    {{.Total}} connected ({{.Located}} located) · generated {{.Generated}}
  </div>
</header>

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
