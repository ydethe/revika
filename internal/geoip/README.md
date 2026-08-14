# internal/geoip

Coarse, best-effort geographic estimation of an IP address, for the node's
operator-facing `/admin` dashboard (see [`internal/net`](../net/README.md)'s
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

// Optional capability for a backend that can discover the machine's public IP.
type SelfLocator interface {
  LocateSelf(ctx context.Context) (Location, bool)
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
The dashboard's self view (`/admin`) prefers `MetricsServer.SetPublicIP`, the
public IP `revika-node` actively discovers at startup (`net.DiscoverPublicIP`,
via `https://api.ipify.org`), over an address parsed from `host.Addrs()` — that
discovered IP is placed with the ordinary `Locate` call, so it works with either
backend, including the offline MMDB one. Only when no public IP was discovered
does the dashboard fall back to a global advertised address, and then to the
optional `SelfLocator` capability when the configured backend provides it. The
IP API backend implements this by asking its service to infer the caller's
public address, which is useful behind NAT; the offline MMDB backend does not
discover public addresses.

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
  - `LocateSelf` uses the endpoint without an IP suffix and caches the result with
    the same success/failure TTLs as ordinary lookups.
- **`MMDBLocator`** (implemented) — an offline MaxMind **GeoLite2/GeoIP2 City** database
  (`.mmdb`) read via the pure-Go `github.com/oschwald/maxminddb-golang/v2`. Built with
  `OpenMMDB(path)`; `Close()` it at shutdown. It makes **no network calls** and discloses
  no address to any third party, so it is the privacy-preserving backend. The operator
  points the node at a single file: `revika-node -geoip=/path/to/GeoLite2-City.mmdb`
  (not a directory — a MaxMind database is one self-contained file). A **City** database
  is required for map markers; the Country-only database carries no latitude/longitude, so
  every lookup against it resolves to not-located. A missing/invalid file logs a warning and
  disables geolocation rather than failing node startup. `OpenMMDB` errors on a bad path;
  a miss, a decode error, or a record with no coordinates (including Null-Island `(0,0)`)
  all resolve to not-located. `mmdbwriter` is a test-only dependency used to synthesize a
  tiny City database in `mmdb_test.go` — no binary fixture is committed.

## Tests

`geoip_test.go` covers `IsGlobal`'s classification table, that `Locate` skips
non-global IPs with no network call, the fetch + cache path (asserting exactly one
upstream hit across two lookups), and that an upstream failure resolves to
not-located. The `/admin` rendering that consumes this package is tested in
`internal/net` (`admin_page_test.go`).
