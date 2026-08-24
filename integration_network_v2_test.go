//go:build v2direct

package revika

// V2 (direct go-libp2p) integration tests. Built only with the "v2direct" tag,
// which also compiles the dormant internal/network package.

import (
	"context"
	"testing"
	"time"

	"github.com/revika/revika/internal/network"
)

// contextWithTimeout creates a context with a specified timeout in seconds.
func contextWithTimeout(t *testing.T, seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
}

// networkNewHost creates a new libp2p Host.
func networkNewHost(ctx context.Context, networkType string) (*network.Host, error) {
	return network.NewHost(ctx, network.NetworkType(networkType))
}

// TestPhase2NetworkHosts tests libp2p host creation and peer management.
func TestPhase2NetworkHosts(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 10)
	defer cancel()

	// Create two network hosts
	host1, err := networkNewHost(ctx, "Private")
	if err != nil {
		t.Fatalf("failed to create host 1: %v", err)
	}
	defer host1.Close()

	host2, err := networkNewHost(ctx, "Private")
	if err != nil {
		t.Fatalf("failed to create host 2: %v", err)
	}
	defer host2.Close()

	// Verify both have unique peer IDs
	id1 := host1.ID()
	id2 := host2.ID()

	if id1 == "" || id2 == "" {
		t.Fatal("peer IDs should not be empty")
	}

	if id1 == id2 {
		t.Fatal("peer IDs should be unique")
	}

	t.Log("✓ Phase 2 network hosts test passed")
	t.Logf("  - Created host 1: %s", id1)
	t.Logf("  - Created host 2: %s", id2)
}
