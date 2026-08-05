package net

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"

	"revika/internal/store"
)

// loadNode builds a server host that answers the balance protocol with src (nil
// = no load source configured). Returns the host to dial.
func loadNode(t *testing.T, src LoadSource) host.Host {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	srv := NewServer(store.NewMemStore(), nil)
	if src != nil {
		srv.SetLoadSource(src)
	}
	srv.Register(h)
	return h
}

func TestQueryLoadRoundTrip(t *testing.T) {
	want := LoadReport{UsedBytes: 512, CapacityBytes: 2048, Shards: 3}
	server := loadNode(t, func() (LoadReport, error) { return want, nil })
	client := clientHost(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := QueryLoad(ctx, client, server.ID())
	if err != nil {
		t.Fatalf("QueryLoad: %v", err)
	}
	if got != want {
		t.Fatalf("QueryLoad = %+v, want %+v", got, want)
	}
	if got.Frac() != 0.25 {
		t.Fatalf("Frac() = %v, want 0.25", got.Frac())
	}
	if got.FreeBytes() != 1536 {
		t.Fatalf("FreeBytes() = %d, want 1536", got.FreeBytes())
	}
}

// TestQueryLoadNoSource confirms a node without a load source fails the query
// closed (an error), rather than advertising a misleading empty report.
func TestQueryLoadNoSource(t *testing.T) {
	server := loadNode(t, nil)
	client := clientHost(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := QueryLoad(ctx, client, server.ID()); err == nil {
		t.Fatal("QueryLoad against a source-less node returned nil error")
	}
}
