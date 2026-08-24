package node

import (
	"path/filepath"
	"testing"
)

func TestNewServer_Success(t *testing.T) {
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	srv, err := NewServer(storeDir, ledgerPath, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Stop()

	if srv.store == nil {
		t.Errorf("expected non-nil store")
	}
	if srv.backend == nil {
		t.Errorf("expected non-nil backend")
	}
	if srv.ledger == nil {
		t.Errorf("expected non-nil ledger")
	}
}

func TestServer_Start_Stop(t *testing.T) {
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	srv, err := NewServer(storeDir, ledgerPath, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestServer_GetPeerID(t *testing.T) {
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	srv, err := NewServer(storeDir, ledgerPath, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Stop()

	// Without a live daemon GetPeerID returns ""; this only asserts it never panics.
	_ = srv.GetPeerID()
}

func TestServer_GetStats_EmptyNode(t *testing.T) {
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	srv, err := NewServer(storeDir, ledgerPath, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Stop()

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	stats, err := srv.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if stats["shards"] != 0 {
		t.Errorf("expected 0 shards, got %v", stats["shards"])
	}

	if stats["total_size"] != int64(0) {
		t.Errorf("expected 0 total size, got %v", stats["total_size"])
	}

	if stats["connected_peers"] != 0 {
		t.Errorf("expected 0 connected peers, got %v", stats["connected_peers"])
	}
}

func TestServer_Multiple_Instances(t *testing.T) {
	tmpDir := t.TempDir()
	storeDir1 := filepath.Join(tmpDir, "store1")
	ledgerPath1 := filepath.Join(tmpDir, "ledger1.json")

	storeDir2 := filepath.Join(tmpDir, "store2")
	ledgerPath2 := filepath.Join(tmpDir, "ledger2.json")

	srv1, err := NewServer(storeDir1, ledgerPath1, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewServer 1 failed: %v", err)
	}
	defer srv1.Stop()

	srv2, err := NewServer(storeDir2, ledgerPath2, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("NewServer 2 failed: %v", err)
	}
	defer srv2.Stop()

	if err := srv1.Start(); err != nil {
		t.Fatalf("Start 1 failed: %v", err)
	}

	if err := srv2.Start(); err != nil {
		t.Fatalf("Start 2 failed: %v", err)
	}
}
