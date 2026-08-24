package revika

// Package revika_test provides end-to-end integration tests for Phase 1.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/revika/revika/internal/crypto"
	"github.com/revika/revika/internal/daemon"
	"github.com/revika/revika/internal/ledger"
	"github.com/revika/revika/internal/node"
	"github.com/revika/revika/internal/shard"
	"github.com/revika/revika/internal/store"
	"github.com/revika/revika/pkg/model"
)

// TestPhase1Integration demonstrates the full Phase 1 workflow:
// 1. Derive encryption keys
// 2. Encrypt file
// 3. Split into shards
// 4. Store shards persistently
// 5. Retrieve shards
// 6. Reconstruct file
// 7. Decrypt to recover original
func TestPhase1Integration(t *testing.T) {
	// Setup
	tmpDir, err := ioutil.TempDir("", "revika-integration-test-")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Original file content
	originalContent := []byte("This is the secret data that needs to be stored securely across the network. " +
		"It will be encrypted, split into shards, and distributed to multiple nodes. " +
		"Any 3 of the 5 shards can reconstruct the original file.")

	password := "super-secret-password-123"

	// Step 1: Derive encryption keys
	kd := &crypto.KeyDerivation{}
	masterKey, err := kd.DeriveUserMasterKey(password)
	if err != nil {
		t.Fatalf("failed to derive master key: %v", err)
	}

	fileContentHash := sha256.Sum256(originalContent)
	perFileKey, err := kd.DerivePerFileKey(masterKey, fileContentHash)
	if err != nil {
		t.Fatalf("failed to derive per-file key: %v", err)
	}

	if len(perFileKey) != 32 {
		t.Fatalf("per-file key should be 32 bytes, got %d", len(perFileKey))
	}

	// Step 2: Encrypt file
	fe := &crypto.FileEncryption{}
	encryptedContent, err := fe.EncryptFile(originalContent, perFileKey)
	if err != nil {
		t.Fatalf("failed to encrypt file: %v", err)
	}

	// Verify encrypted content is different from original
	if bytes.Equal(encryptedContent, originalContent) {
		t.Fatal("encrypted content should not equal original")
	}

	// Step 3: Split into shards using Reed-Solomon
	splitter := shard.NewShardSplitterDefault() // k=3, m=2
	shards, err := splitter.SplitFile(encryptedContent)
	if err != nil {
		t.Fatalf("failed to split file: %v", err)
	}

	if len(shards) != 5 {
		t.Fatalf("expected 5 shards (k=3, m=2), got %d", len(shards))
	}

	// Verify all shard IDs are unique and valid
	seenIDs := make(map[string]bool)
	for _, s := range shards {
		if s.ID == "" {
			t.Fatal("shard ID should not be empty")
		}
		if seenIDs[s.ID] {
			t.Fatal("duplicate shard ID")
		}
		seenIDs[s.ID] = true

		// Verify shard ID matches content
		if !shard.VerifyShardID(s) {
			t.Fatalf("shard ID verification failed for shard %d", s.Index)
		}
	}

	// Step 4: Store shards persistently
	nodeStore, err := store.NewLocalFileStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create node store: %v", err)
	}

	for _, s := range shards {
		if err := nodeStore.PutShard(s.ID, s.Bytes); err != nil {
			t.Fatalf("failed to store shard %s: %v", s.ID, err)
		}
	}

	// Verify all shards are persisted
	storedShardIDs, err := nodeStore.ListShards()
	if err != nil {
		t.Fatalf("failed to list shards: %v", err)
	}

	if len(storedShardIDs) != 5 {
		t.Fatalf("expected 5 stored shards, got %d", len(storedShardIDs))
	}

	// Step 5: Retrieve shards (simulate node failure - use only first 3 shards)
	reconstructionShards := make([]model.ShardInfo, 0, 3)
	for i := 0; i < 3; i++ {
		shardID := shards[i].ID
		shardData, err := nodeStore.GetShard(shardID)
		if err != nil {
			t.Fatalf("failed to retrieve shard %s: %v", shardID, err)
		}

		reconstructionShards = append(reconstructionShards, model.ShardInfo{
			ID:    shardID,
			Bytes: shardData,
			Index: shards[i].Index,
		})
	}

	// Step 6: Reconstruct encrypted file from k=3 shards
	reconstructor := shard.NewShardReconstructor()

	reconstructedEncrypted, err := reconstructor.ReconstructFile(reconstructionShards, 3, 2, int64(len(encryptedContent)))
	if err != nil {
		t.Fatalf("failed to reconstruct file: %v", err)
	}

	// Verify reconstruction matches original (automatic trimming in ReconstructFile)
	if !bytes.Equal(reconstructedEncrypted, encryptedContent) {
		t.Fatal("reconstructed encrypted content does not match original")
	}

	// Step 7: Decrypt to recover original
	decrypted, err := fe.DecryptFile(reconstructedEncrypted, perFileKey)
	if err != nil {
		t.Fatalf("failed to decrypt file: %v", err)
	}

	// Verify decrypted content matches original
	if !bytes.Equal(decrypted, originalContent) {
		t.Fatal("decrypted content does not match original")
	}

	t.Log("✓ Phase 1 integration test passed")
	t.Log("  - Encrypted and split", len(originalContent), "bytes into", len(shards), "shards")
	t.Log("  - Stored shards persistently")
	t.Log("  - Reconstructed from 3 of 5 shards")
	t.Log("  - Decrypted to recover original content")
}

// TestPhase1KeySharing demonstrates key wrapping for sharing files with others.
func TestPhase1KeySharing(t *testing.T) {
	// Create device B's keypair (in practice, obtained from libp2p identity)
	deviceBPrivateKey, err := randomX25519PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate device B keypair: %v", err)
	}
	deviceBPublicKey := deviceBPrivateKey.PublicKey().Bytes()

	// Device A encrypts a file
	kd := &crypto.KeyDerivation{}
	masterKeyA, _ := kd.DeriveUserMasterKey("device-a-password")
	fileHash := sha256.Sum256([]byte("shared file content"))
	perFileKeyA, _ := kd.DerivePerFileKey(masterKeyA, fileHash)

	// Device A wraps the per-file key for Device B to access
	kw := &crypto.KeyWrapping{}
	wrappedKey, err := kw.WrapKey(perFileKeyA, deviceBPublicKey)
	if err != nil {
		t.Fatalf("failed to wrap key: %v", err)
	}

	// Device B unwraps the key with their private key
	deviceBPrivateKeyBytes := deviceBPrivateKey.PrivateKey()
	unwrappedKey, err := kw.UnwrapKey(wrappedKey, deviceBPrivateKeyBytes)
	if err != nil {
		t.Fatalf("failed to unwrap key: %v", err)
	}

	// Verify Device B can now decrypt with the unwrapped key
	if !bytes.Equal(unwrappedKey, perFileKeyA) {
		t.Fatal("unwrapped key does not match original")
	}

	t.Log("✓ Key sharing test passed")
	t.Log("  - Device A shared encrypted key with Device B")
	t.Log("  - Device B successfully unwrapped the key")
	t.Log("  - Both devices can now access the same encrypted file")
}

// TestPhase1ShardResilience demonstrates that the system can recover from
// up to m=2 shard losses.
func TestPhase1ShardResilience(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "revika-resilience-test-")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Original content
	originalContent := make([]byte, 10*1024) // 10KB
	rand.Read(originalContent)

	// Encrypt and split
	kd := &crypto.KeyDerivation{}
	masterKey, _ := kd.DeriveUserMasterKey("password")
	fileHash := sha256.Sum256(originalContent)
	perFileKey, _ := kd.DerivePerFileKey(masterKey, fileHash)

	fe := &crypto.FileEncryption{}
	encrypted, _ := fe.EncryptFile(originalContent, perFileKey)

	splitter := shard.NewShardSplitterDefault()
	shards, _ := splitter.SplitFile(encrypted)

	// Store shards
	nodeStore, _ := store.NewLocalFileStore(tmpDir)
	for _, s := range shards {
		nodeStore.PutShard(s.ID, s.Bytes)
	}

	// Simulate losing 2 shards (all m=2 parity shards)
	// We should still be able to reconstruct with the remaining 3 data shards
	reconstructor := shard.NewShardReconstructor()

	// Use only shards 0, 1, 2 (the k=3 data shards)
	selectedShards := make([]model.ShardInfo, 0, 3)
	for i := 0; i < 3; i++ {
		shardData, _ := nodeStore.GetShard(shards[i].ID)
		selectedShards = append(selectedShards, model.ShardInfo{
			ID:    shards[i].ID,
			Bytes: shardData,
			Index: shards[i].Index,
		})
	}

	// Reconstruct and decrypt (automatic trimming in ReconstructFile)
	reconstructed, _ := reconstructor.ReconstructFile(selectedShards, 3, 2, int64(len(encrypted)))
	decrypted, _ := fe.DecryptFile(reconstructed, perFileKey)

	if !bytes.Equal(decrypted, originalContent) {
		t.Fatal("resilience test failed: decrypted content does not match")
	}

	t.Log("✓ Shard resilience test passed")
	t.Log("  - Lost 2 parity shards (all m shards)")
	t.Log("  - Successfully reconstructed from 3 data shards (k shards)")
	t.Log("  - Recovered original content")
}

// Helper: Generate random X25519 private key
func randomX25519PrivateKey() (*X25519PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &X25519PrivateKey{priv: priv}, nil
}

// X25519PrivateKey wraps ecdh.PrivateKey for testing
type X25519PrivateKey struct {
	priv *ecdh.PrivateKey
}

func (k *X25519PrivateKey) PrivateKey() []byte {
	return k.priv.Bytes()
}

func (k *X25519PrivateKey) PublicKey() *X25519PublicKey {
	return &X25519PublicKey{k.priv.PublicKey()}
}

type X25519PublicKey struct {
	pub *ecdh.PublicKey
}

func (k *X25519PublicKey) Bytes() []byte {
	return k.pub.Bytes()
}

// TestPhase2LedgerManagement tests ledger operations for tracking files and access
func TestPhase2LedgerManagement(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "revika-ledger-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ledgerPath := tmpDir + "/ledger.json"

	// Load empty ledger
	ledger, err := ledgerLoad(ledgerPath)
	if err != nil {
		t.Fatalf("failed to load ledger: %v", err)
	}

	// Create a tree
	if err := ledger.AddTree("tree1", "/data"); err != nil {
		t.Fatalf("failed to add tree: %v", err)
	}

	// Add a file to the tree
	shards := []model.ShardRef{
		{Hash: "shard1"}, {Hash: "shard2"}, {Hash: "shard3"}, {Hash: "shard4"}, {Hash: "shard5"},
	}
	if err := ledger.AddFile("tree1", "file1", "/data/document.txt", "sha256:abc123", shards, 3, 2); err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	// Grant access to a peer
	if err := ledger.GrantAccess("tree1", "peer123"); err != nil {
		t.Fatalf("failed to grant access: %v", err)
	}

	// Save ledger
	if err := ledger.Save(ledgerPath); err != nil {
		t.Fatalf("failed to save ledger: %v", err)
	}

	// Reload and verify
	ledger2, err := ledgerLoad(ledgerPath)
	if err != nil {
		t.Fatalf("failed to reload ledger: %v", err)
	}

	trees, err := ledger2.ListTrees()
	if err != nil {
		t.Fatalf("failed to list trees: %v", err)
	}

	if len(trees) != 1 {
		t.Fatalf("expected 1 tree, got %d", len(trees))
	}

	tree, err := ledger2.GetTree("tree1")
	if err != nil {
		t.Fatalf("failed to get tree: %v", err)
	}

	if len(tree.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(tree.Files))
	}

	t.Log("✓ Phase 2 ledger management test passed")
	t.Log("  - Created tree and added file")
	t.Log("  - Granted access to peer")
	t.Log("  - Saved and reloaded ledger")
}

// TestPhase2DaemonIPC tests the daemon's IPC command handling
func TestPhase2DaemonIPC(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "revika-daemon-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ledgerPath := tmpDir + "/ledger.json"
	ipcAddr := tmpDir + "/daemon.sock"

	// Create daemon service
	svc, err := daemonNewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	defer svc.Stop()

	// Test IPC commands
	tests := []struct {
		name   string
		method string
		params []byte
	}{
		{
			name:   "connect",
			method: "connect",
			params: marshalParams(map[string]string{"network_type": "Public"}),
		},
		{
			name:   "pwd",
			method: "pwd",
			params: []byte("null"),
		},
		{
			name:   "ls",
			method: "ls",
			params: marshalParams(map[string]string{"path": "/"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &model.IPCRequest{
				Method: tt.method,
				Params: tt.params,
				ID:     1,
			}

			resp, err := svc.HandleIPCRequest(req)
			if err != nil {
				t.Errorf("HandleIPCRequest failed: %v", err)
				return
			}

			if resp.Error != nil && tt.method != "unknown" {
				t.Errorf("expected no error, got: %v", resp.Error.Message)
			}

			if len(resp.Result) == 0 && tt.method != "unknown" {
				t.Errorf("expected non-empty result")
			}
		})
	}

	t.Log("✓ Phase 2 daemon IPC test passed")
}

// TestPhase2NodeServerStorage tests the node server's shard storage
func TestPhase2NodeServerStorage(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "revika-node-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storeDir := tmpDir + "/store"
	ledgerPath := tmpDir + "/ledger.json"

	// Create and start node server
	srv, err := nodeNewServer(storeDir, ledgerPath, "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("failed to create node server: %v", err)
	}
	defer srv.Stop()

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start node server: %v", err)
	}

	// Get initial stats
	stats, err := srv.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}

	if stats["shards"] != 0 {
		t.Errorf("expected 0 shards initially, got %v", stats["shards"])
	}

	t.Log("✓ Phase 2 node server storage test passed")
	t.Logf("  - Node started with peer ID: %s", srv.GetPeerID())
	t.Logf("  - Initial storage stats: %+v", stats)
}

// Benchmark: Full encryption + split for 100MB file
func BenchmarkPhase1FullWorkflow(b *testing.B) {
	tmpDir, _ := ioutil.TempDir("", "revika-bench-")
	defer os.RemoveAll(tmpDir)

	fileData := make([]byte, 100*1024*1024) // 100MB
	rand.Read(fileData)

	kd := &crypto.KeyDerivation{}
	masterKey, _ := kd.DeriveUserMasterKey("password")
	fileHash := sha256.Sum256(fileData)
	perFileKey, _ := kd.DerivePerFileKey(masterKey, fileHash)

	fe := &crypto.FileEncryption{}
	encrypted, _ := fe.EncryptFile(fileData, perFileKey)

	splitter := shard.NewShardSplitterDefault()
	nodeStore, _ := store.NewLocalFileStore(tmpDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shards, _ := splitter.SplitFile(encrypted)
		for _, s := range shards {
			nodeStore.PutShard(s.ID, s.Bytes)
		}
	}
}

// ============================================================================
// Phase 2 Helper Functions
// ============================================================================

// ledgerLoad loads a ledger from disk
func ledgerLoad(path string) (*ledger.Ledger, error) {
	return ledger.Load(path)
}

// daemonNewService creates a new daemon Service
func daemonNewService(ledgerPath string, apiAddr string, ipcAddr string) (*daemon.Service, error) {
	return daemon.NewService(ledgerPath, apiAddr, ipcAddr)
}

// marshalParams marshals parameters to JSON bytes
func marshalParams(params interface{}) []byte {
	data, err := json.Marshal(params)
	if err != nil {
		return []byte("null")
	}
	return data
}

// nodeNewServer creates a new node Server
func nodeNewServer(storeDir string, ledgerPath string, apiAddr string) (*node.Server, error) {
	return node.NewServer(storeDir, ledgerPath, apiAddr)
}
