// Package geoip estimates the approximate geographic position of an IP address
// for the node's operator-facing /admin dashboard (internal/net MetricsServer).
//
// It is deliberately a small, pluggable seam: the network layer depends only on
// the Locator interface, so the position source can be swapped without touching
// the dashboard. Two things stay true regardless of backend:
//
//   - Only *global* IPs are ever located. Private, loopback, link-local and
//     unspecified addresses (a node reached over LAN, localhost, or a VPN) are
//     reported as not-locatable, so they are never sent to an external service
//     and never plotted at a bogus (0,0).
//   - Positions are best-effort *estimates*. IP geolocation is coarse (often only
//     city/country accurate), so the dashboard presents markers as approximate.
//
// Two backends exist, both off by default (see revika-node's -geoip flag):
// IPAPILocator, an opt-in client for the free ip-api.com service (sends peer
// public IPs to a third party), and MMDBLocator, an offline MaxMind GeoLite2/
// GeoIP2 City (.mmdb) reader that makes no network calls and is the privacy-
// preserving choice for operators who ship the database.
package geoip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Location is a coarse, best-effort estimate of where an IP address is. The zero
// value is meaningless on its own — a caller learns whether a location is known
// from the Locator's ok return, not from the fields.
type Location struct {
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	City        string  `json:"city,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
}

// Locator estimates the position of an IP. It returns ok=false when it cannot —
// a non-global IP (IsGlobal false), a lookup failure, or a disabled/misconfigured
// backend — so callers render such peers without a map marker rather than at a
// wrong position. Implementations must be safe for concurrent use.
type Locator interface {
	Locate(ctx context.Context, ip netip.Addr) (Location, bool)
}

// IsGlobal reports whether ip is a publicly-routable address worth (and safe to)
// geolocate. It excludes loopback, private (RFC 1918 / ULA), link-local,
// multicast and unspecified addresses — the ones a peer is reached over on a LAN,
// localhost, or a private overlay, which carry no meaningful public position and
// must never be handed to an external geolocation service.
func IsGlobal(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return !(ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified())
}

// ipAPIEndpoint is the free ip-api.com JSON endpoint. It is plain HTTP because
// TLS requires a paid plan; the operator opts in knowing the request (peer IP,
// in the clear) leaves the machine. Overridable in tests via IPAPILocator.Endpoint.
const ipAPIEndpoint = "http://ip-api.com/json/"

// Cache TTLs: a successful lookup is stable for a while (an IP rarely moves
// cities within an hour); a failure is retried sooner so a transient error or a
// rate-limit does not blank a peer for an hour.
const (
	ipAPISuccessTTL = time.Hour
	ipAPIFailureTTL = 5 * time.Minute
)

// IPAPILocator estimates positions via the free ip-api.com service, caching
// results in memory so repeated dashboard loads do not re-query (and stay well
// under the service's per-IP rate limit). It is safe for concurrent use. Zero
// value is not usable — build it with NewIPAPILocator.
//
// Only IsGlobal IPs are ever sent; everything else short-circuits to not-located
// without a network call.
type IPAPILocator struct {
	// Endpoint is the JSON base URL an IP is appended to. Defaults to ip-api.com;
	// overridden in tests to point at a local stub. Not mutated after construction.
	Endpoint string

	client *http.Client
	mu     sync.Mutex
	cache  map[netip.Addr]cacheEntry
}

type cacheEntry struct {
	loc Location
	ok  bool
	at  time.Time
}

// NewIPAPILocator builds an IPAPILocator with a bounded per-request timeout and
// an empty cache.
func NewIPAPILocator() *IPAPILocator {
	return &IPAPILocator{
		Endpoint: ipAPIEndpoint,
		client:   &http.Client{Timeout: 4 * time.Second},
		cache:    make(map[netip.Addr]cacheEntry),
	}
}

// Locate returns ip's estimated position, consulting the in-memory cache first.
// Non-global IPs never reach the network. A per-request timeout (and the caller's
// ctx) bound the lookup; any error resolves to ok=false, cached briefly.
func (l *IPAPILocator) Locate(ctx context.Context, ip netip.Addr) (Location, bool) {
	if !IsGlobal(ip) {
		return Location{}, false
	}
	if loc, ok, fresh := l.cached(ip); fresh {
		return loc, ok
	}
	loc, ok := l.fetch(ctx, ip)
	l.mu.Lock()
	l.cache[ip] = cacheEntry{loc: loc, ok: ok, at: time.Now()}
	l.mu.Unlock()
	return loc, ok
}

// cached returns a still-valid cache entry for ip. fresh is false when there is
// no entry or it has aged past the TTL for its outcome.
func (l *IPAPILocator) cached(ip netip.Addr) (loc Location, ok, fresh bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, present := l.cache[ip]
	if !present {
		return Location{}, false, false
	}
	ttl := ipAPISuccessTTL
	if !e.ok {
		ttl = ipAPIFailureTTL
	}
	if time.Since(e.at) >= ttl {
		return Location{}, false, false
	}
	return e.loc, e.ok, true
}

// fetch performs one ip-api.com query. The ?fields mask requests exactly what the
// dashboard shows, keeping the response small.
func (l *IPAPILocator) fetch(ctx context.Context, ip netip.Addr) (Location, bool) {
	url := l.Endpoint + ip.String() + "?fields=status,country,countryCode,city,lat,lon"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Location{}, false
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return Location{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Location{}, false
	}
	var body struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Location{}, false
	}
	if body.Status != "success" {
		return Location{}, false
	}
	return Location{
		Lat:         body.Lat,
		Lon:         body.Lon,
		City:        body.City,
		Country:     body.Country,
		CountryCode: body.CountryCode,
	}, true
}
