package geoip

import (
	"context"
	"fmt"
	"net/netip"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// MMDBLocator estimates positions from an offline MaxMind GeoLite2 / GeoIP2
// *City* database (.mmdb). Unlike IPAPILocator it makes no network calls and
// discloses no address to any third party, so it is the privacy-preserving
// backend an operator can ship with the node. Lookups read a memory-mapped file
// and need no cache. The zero value is unusable — build it with OpenMMDB, and
// Close it at shutdown.
//
// A City database is required for map markers: the Country-only database carries
// no latitude/longitude, so every lookup against it resolves to not-located.
type MMDBLocator struct {
	db *maxminddb.Reader
}

// OpenMMDB memory-maps the MaxMind database at path. It returns an error if the
// file is missing or not a valid .mmdb, so the node logs and falls back to no
// geolocation rather than serving a silently-dead map.
func OpenMMDB(path string) (*MMDBLocator, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open mmdb %q: %w", path, err)
	}
	return &MMDBLocator{db: db}, nil
}

// Close releases the underlying database. It must not race a Locate call; the
// node calls it once, on shutdown, after the metrics server has stopped.
func (l *MMDBLocator) Close() error {
	return l.db.Close()
}

// mmdbCityRecord is the subset of the GeoLite2 / GeoIP2 City schema the dashboard
// shows. The maxminddb tags follow MaxMind's documented record layout; localized
// names are read in English ("en"), the key always present in the GeoLite2 build.
type mmdbCityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Locate looks ip up in the offline database. Non-global IPs short-circuit to
// not-located (the Locator contract) without touching the DB. A miss, a lookup
// or decode error, or a record carrying no coordinates all resolve to ok=false
// so the peer renders without a marker rather than at a bogus (0,0). The context
// is unused — the lookup is a local memory read.
func (l *MMDBLocator) Locate(_ context.Context, ip netip.Addr) (Location, bool) {
	if !IsGlobal(ip) {
		return Location{}, false
	}
	res := l.db.Lookup(ip)
	if err := res.Err(); err != nil || !res.Found() {
		return Location{}, false
	}
	var rec mmdbCityRecord
	if err := res.Decode(&rec); err != nil {
		return Location{}, false
	}
	// A record without coordinates (a Country-only DB, or a block MaxMind cannot
	// place more precisely) has no map position. (0,0) is Null Island in the
	// Atlantic, never a real peer — treat it as not-located.
	if rec.Location.Latitude == 0 && rec.Location.Longitude == 0 {
		return Location{}, false
	}
	return Location{
		Lat:         rec.Location.Latitude,
		Lon:         rec.Location.Longitude,
		City:        rec.City.Names["en"],
		Country:     rec.Country.Names["en"],
		CountryCode: rec.Country.ISOCode,
	}, true
}
