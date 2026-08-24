package kubo

import (
	"context"
	"os"
	"testing"

	"github.com/revika/revika/pkg/model"
)

func TestNewAdapter_LazyConstruction(t *testing.T) {
	// Construction must not require a running daemon.
	a, err := NewAdapter("127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewAdapter failed: %v", err)
	}
	if a == nil || a.sh == nil {
		t.Fatal("expected non-nil adapter and shell")
	}
}

func TestNewAdapter_DefaultAddr(t *testing.T) {
	a, err := NewAdapter("")
	if err != nil {
		t.Fatalf("NewAdapter with empty addr failed: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil adapter")
	}
}

// TestExpectedCID_ReconcilesWithShardID verifies the core contract: the CIDv1
// (raw, sha2-256) multihash digest equals model.ComputeShardID(data).
func TestExpectedCID_ReconcilesWithShardID(t *testing.T) {
	data := []byte("revika encrypted shard payload")

	cidStr, err := ExpectedCID(data)
	if err != nil {
		t.Fatalf("ExpectedCID failed: %v", err)
	}

	shardID := model.ComputeShardID(data)

	ok, err := CIDMatchesSHA256(cidStr, shardID)
	if err != nil {
		t.Fatalf("CIDMatchesSHA256 failed: %v", err)
	}
	if !ok {
		t.Fatalf("CID %s does not reconcile with shard ID %s", cidStr, shardID)
	}
}

func TestCIDMatchesSHA256_Mismatch(t *testing.T) {
	cidStr, err := ExpectedCID([]byte("one"))
	if err != nil {
		t.Fatalf("ExpectedCID failed: %v", err)
	}

	otherID := model.ComputeShardID([]byte("two"))
	ok, err := CIDMatchesSHA256(cidStr, otherID)
	if err != nil {
		t.Fatalf("CIDMatchesSHA256 failed: %v", err)
	}
	if ok {
		t.Fatal("expected mismatch between CID and a different shard ID")
	}
}

func TestCIDMatchesSHA256_InvalidCID(t *testing.T) {
	if _, err := CIDMatchesSHA256("not-a-cid", "deadbeef"); err == nil {
		t.Fatal("expected error for invalid CID")
	}
}

// TestAddGetBlock_LiveDaemon exercises the real Kubo RPC path. It is skipped
// unless IPFS_API points at a reachable daemon, so `go test ./...` passes in
// CI without one.
func TestAddGetBlock_LiveDaemon(t *testing.T) {
	apiAddr := os.Getenv("IPFS_API")
	if apiAddr == "" {
		t.Skip("IPFS_API not set; skipping live-daemon test")
	}

	a, err := NewAdapter(apiAddr)
	if err != nil {
		t.Fatalf("NewAdapter failed: %v", err)
	}

	ctx := context.Background()
	data := []byte("live daemon round trip")

	cidStr, err := a.AddBlock(ctx, data)
	if err != nil {
		t.Fatalf("AddBlock failed: %v", err)
	}

	ok, err := CIDMatchesSHA256(cidStr, model.ComputeShardID(data))
	if err != nil || !ok {
		t.Fatalf("returned CID %s does not reconcile with sha2-256 (ok=%v, err=%v)", cidStr, ok, err)
	}

	got, err := a.GetBlock(ctx, cidStr)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("round trip mismatch: got %q want %q", got, data)
	}
}
