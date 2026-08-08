package geoip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestIsGlobal(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},   // loopback
		{"::1", false},         // loopback v6
		{"10.0.0.1", false},    // private
		{"192.168.1.5", false}, // private
		{"172.16.3.4", false},  // private
		{"169.254.1.1", false}, // link-local
		{"fe80::1", false},     // link-local v6
		{"fd00::1", false},     // ULA (private v6)
		{"224.0.0.1", false},   // multicast
		{"0.0.0.0", false},     // unspecified
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := IsGlobal(ip); got != c.want {
			t.Errorf("IsGlobal(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if IsGlobal(netip.Addr{}) {
		t.Error("IsGlobal(zero Addr) = true, want false")
	}
}

// stubIPAPI returns a locator pointed at a test server that answers a fixed
// success payload, plus a pointer to the hit counter so a test can assert caching.
func stubIPAPI(t *testing.T) (*IPAPILocator, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `{"status":"success","country":"United States","countryCode":"US","city":"Mountain View","lat":37.386,"lon":-122.0838}`)
	}))
	t.Cleanup(ts.Close)
	l := NewIPAPILocator()
	l.Endpoint = ts.URL + "/"
	return l, &hits
}

func TestIPAPILocatorSkipsNonGlobal(t *testing.T) {
	l := NewIPAPILocator()
	// Point at a URL that would fail loudly if ever hit.
	l.Endpoint = "http://127.0.0.1:0/should-not-be-called/"
	if _, ok := l.Locate(context.Background(), netip.MustParseAddr("192.168.0.10")); ok {
		t.Fatal("Locate(private IP) = ok, want not located (and no network call)")
	}
	if _, ok := l.Locate(context.Background(), netip.MustParseAddr("127.0.0.1")); ok {
		t.Fatal("Locate(loopback) = ok, want not located")
	}
}

func TestIPAPILocatorFetchAndCache(t *testing.T) {
	l, hits := stubIPAPI(t)
	ip := netip.MustParseAddr("8.8.8.8")

	loc, ok := l.Locate(context.Background(), ip)
	if !ok {
		t.Fatal("Locate(8.8.8.8) = not ok, want located")
	}
	if loc.City != "Mountain View" || loc.CountryCode != "US" {
		t.Fatalf("location = %+v, want Mountain View/US", loc)
	}
	if loc.Lat == 0 || loc.Lon == 0 {
		t.Fatalf("location coords = %v,%v, want non-zero", loc.Lat, loc.Lon)
	}

	// A second lookup of the same IP is served from cache — no new request.
	if _, ok := l.Locate(context.Background(), ip); !ok {
		t.Fatal("second Locate = not ok")
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("upstream hit %d times, want 1 (second call should be cached)", n)
	}
}

func TestIPAPILocatorFailure(t *testing.T) {
	// A server reporting a lookup failure resolves to not-located, not an error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"fail","message":"reserved range"}`)
	}))
	t.Cleanup(ts.Close)
	l := NewIPAPILocator()
	l.Endpoint = ts.URL + "/"
	if _, ok := l.Locate(context.Background(), netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("Locate against a failing upstream = ok, want not located")
	}
}
