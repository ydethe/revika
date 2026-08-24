//go:build v2direct

package network

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

func TestNewHost_Public(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkPublic)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	if h.ID() == "" {
		t.Errorf("expected non-empty peer ID")
	}

	if h.GetNetworkType() != NetworkPublic {
		t.Errorf("expected NetworkPublic, got %v", h.GetNetworkType())
	}

	if h.dht == nil {
		t.Errorf("expected DHT to be initialized for Public network")
	}
}

func TestNewHost_Hybrid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkHybrid)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	if h.GetNetworkType() != NetworkHybrid {
		t.Errorf("expected NetworkHybrid, got %v", h.GetNetworkType())
	}

	if h.dht == nil {
		t.Errorf("expected DHT to be initialized for Hybrid network")
	}
}

func TestNewHost_Private(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	if h.GetNetworkType() != NetworkPrivate {
		t.Errorf("expected NetworkPrivate, got %v", h.GetNetworkType())
	}

	if h.dht != nil {
		t.Errorf("expected DHT to be nil for Private network")
	}
}

func TestHost_ID_NonEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	id := h.ID()
	if id == "" {
		t.Errorf("expected non-empty peer ID")
	}

	// Peer ID should be a valid format (Qm... for base32)
	if len(id) < 10 {
		t.Errorf("peer ID too short: %s", id)
	}
}

func TestHost_RegisterProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	// Register a test handler
	testHandler := func(stream network.Stream) error {
		return nil
	}

	h.RegisterProtocol(ProtoPutShard, testHandler)

	// Verify it's registered in the router
	handler, exists := h.GetRouter().registry.Get(string(ProtoPutShard))
	if !exists {
		t.Errorf("handler not registered in router")
	}
	if handler == nil {
		t.Errorf("expected non-nil handler")
	}
}

func TestHost_GetPeers_Empty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	peers, err := h.GetPeers()
	if err != nil {
		t.Errorf("GetPeers failed: %v", err)
	}

	if len(peers) != 0 {
		t.Errorf("expected 0 peers initially, got %d", len(peers))
	}
}

func TestHost_Close(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify context is cancelled
	select {
	case <-h.ctx.Done():
		// Expected
	case <-time.After(1 * time.Second):
		t.Errorf("context not cancelled after Close")
	}
}

func TestHost_MultipleInstances(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h1, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer h1.Close()

	h2, err := NewHost(ctx, NetworkPrivate)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer h2.Close()

	id1 := h1.ID()
	id2 := h2.ID()

	if id1 == id2 {
		t.Errorf("expected different peer IDs, got same: %s", id1)
	}
}
