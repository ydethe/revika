# internal/geoip

Coarse, best-effort geographic estimation of an IP address, for the node's
operator-facing `/nodes` dashboard (see [`internal/net`](../net/README.md)'s
`MetricsServer`). This is *cartography for operators*, never part of the storage or
trust path — a node stays a dumb, content-blind blob store; where its peers sit on a
map is purely observational.

## The seam

The network layer depends only on the `Locator` interface, so the position source is
swappable without touching the dashboard:

```go
type Locator interface {
    // ok=false when the IP can't be placed: non-global, lookup failure, or a
    // disabled/misconfigured backend. Safe for concurrent use.
    Locate(ctx context.Context, ip netip.Addr) (Location, bool)
}

type Location struct {
    Lat, Lon    float64
    City        string
    Country     string
    CountryCode string
}
```

`MetricsServer.SetGeolocator(Locator)` wires one in; leaving it nil (the default)
disables geolocation and the dashboard renders peers without map markers.

## Two invariants, regardless of backend

- **Only global IPs are ever located.** `IsGlobal` rejects loopback, private
  (RFC 1918 / ULA), link-local, multicast and unspecified addresses. A peer reached
  over LAN, localhost, or a private overlay is reported not-locatable — so its address
  is never sent to an external service and never plotted at a bogus `(0,0)`.
- **Positions are estimates.** IP geolocation is coarse (often only city/country
  accurate); the dashboard presents markers as approximate.

## Backends

- **`IPAPILocator`** (implemented, opt-in) — queries the free
  [ip-api.com](http://ip-api.com) JSON service. Built with `NewIPAPILocator`.
  - Results are cached in memory (`ipAPISuccessTTL` = 1h for a hit, `ipAPIFailureTTL`
    = 5m for a miss) so repeated dashboard loads don't re-query and stay under the
    service's per-IP rate limit.
  - The request is **plain HTTP** (TLS is a paid tier) and carries the peer's public
    IP in the clear to a third party, so it is **off by default** on the node. The
    operator opts in with `revika-node -geoip=ip-api`, which logs a warning noting the
    third-party disclosure. Non-global IPs short-circuit with no network call.
  - `Endpoint` is overridable (tests point it at a local stub); a 4s per-request
    timeout plus the caller's context bound each lookup, and any error resolves to
    not-located (cached briefly) rather than an error.
- **MaxMind GeoLite2 (`.mmdb`)** (planned) — an offline, no-third-party drop-in behind
  the same `Locator` interface. Nothing else changes when it lands; it would be the
  privacy-preserving default for operators who ship the database.

## Tests

`geoip_test.go` covers `IsGlobal`'s classification table, that `Locate` skips
non-global IPs with no network call, the fetch + cache path (asserting exactly one
upstream hit across two lookups), and that an upstream failure resolves to
not-located. The `/nodes` rendering that consumes this package is tested in
`internal/net` (`nodes_page_test.go`).
