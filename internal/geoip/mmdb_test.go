package geoip

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// writeCityMMDB builds a tiny GeoLite2-City-shaped database with one located
// network (8.8.8.0/24 → Mountain View, US) and one country-only network
// (1.1.1.0/24 → Australia, no coordinates), writes it to a temp file, and
// returns the path. This lets the tests exercise MMDBLocator against a real
// on-disk .mmdb without shipping a binary fixture.
func writeCityMMDB(t *testing.T) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoLite2-City",
		IPVersion:               6, // an IPv6 tree also answers IPv4 lookups
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}

	located := mmdbtype.Map{
		"city": mmdbtype.Map{
			"names": mmdbtype.Map{"en": mmdbtype.String("Mountain View")},
		},
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("US"),
			"names":    mmdbtype.Map{"en": mmdbtype.String("United States")},
		},
		"location": mmdbtype.Map{
			"latitude":  mmdbtype.Float64(37.386),
			"longitude": mmdbtype.Float64(-122.0838),
		},
	}
	insert(t, tree, "8.8.8.0/24", located)

	// Country-only record: no location subtree, so no coordinates.
	countryOnly := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("AU"),
			"names":    mmdbtype.Map{"en": mmdbtype.String("Australia")},
		},
	}
	insert(t, tree, "1.1.1.0/24", countryOnly)

	path := filepath.Join(t.TempDir(), "GeoLite2-City-Test.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create mmdb: %v", err)
	}
	defer f.Close()
	if _, err := tree.WriteTo(f); err != nil {
		t.Fatalf("write mmdb: %v", err)
	}
	return path
}

func insert(t *testing.T, tree *mmdbwriter.Tree, cidr string, rec mmdbtype.Map) {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr %q: %v", cidr, err)
	}
	if err := tree.Insert(network, rec); err != nil {
		t.Fatalf("insert %q: %v", cidr, err)
	}
}

func TestMMDBLocatorLocates(t *testing.T) {
	loc, err := OpenMMDB(writeCityMMDB(t))
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	defer loc.Close()

	got, ok := loc.Locate(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("Locate(8.8.8.8) = not located, want located")
	}
	if got.City != "Mountain View" || got.CountryCode != "US" || got.Country != "United States" {
		t.Fatalf("location = %+v, want Mountain View/US/United States", got)
	}
	if got.Lat == 0 || got.Lon == 0 {
		t.Fatalf("coords = %v,%v, want non-zero", got.Lat, got.Lon)
	}
}

func TestMMDBLocatorSkipsNonGlobal(t *testing.T) {
	loc, err := OpenMMDB(writeCityMMDB(t))
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	defer loc.Close()

	// A private IP must never be looked up, even if the DB could answer.
	if _, ok := loc.Locate(context.Background(), netip.MustParseAddr("192.168.1.5")); ok {
		t.Fatal("Locate(private IP) = located, want not located")
	}
}

func TestMMDBLocatorMissAndCountryOnly(t *testing.T) {
	loc, err := OpenMMDB(writeCityMMDB(t))
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	defer loc.Close()

	// A global IP absent from the DB resolves to not-located.
	if _, ok := loc.Locate(context.Background(), netip.MustParseAddr("9.9.9.9")); ok {
		t.Fatal("Locate(absent IP) = located, want not located")
	}
	// A record carrying a country but no coordinates is not plottable.
	if _, ok := loc.Locate(context.Background(), netip.MustParseAddr("1.1.1.1")); ok {
		t.Fatal("Locate(country-only record) = located, want not located (no coords)")
	}
}

func TestOpenMMDBBadPath(t *testing.T) {
	if _, err := OpenMMDB(filepath.Join(t.TempDir(), "does-not-exist.mmdb")); err == nil {
		t.Fatal("OpenMMDB(missing file) = nil error, want error")
	}
	// A file that is not a valid mmdb must also error, not panic.
	bad := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(bad, []byte("not an mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMMDB(bad); err == nil {
		t.Fatal("OpenMMDB(invalid file) = nil error, want error")
	}
}
