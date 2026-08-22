package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// validShardID returns a valid hex-encoded SHA256 shard ID derived from seed.
func validShardID(seed string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(seed)))
}

func createTempDir(t *testing.T) string {
	tmpDir, err := ioutil.TempDir("", "revika-store-test-")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	return tmpDir
}

func TestNewLocalFileStore(t *testing.T) {
	validDir := createTempDir(t)

	tests := []struct {
		name    string
		baseDir string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid directory",
			baseDir: validDir,
			wantErr: false,
		},
		{
			name:    "empty base dir",
			baseDir: "",
			wantErr: true,
			errMsg:  "baseDir cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewLocalFileStore(tt.baseDir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewLocalFileStore() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Fatalf("expected error %q, got %q", tt.errMsg, err.Error())
			}
			if !tt.wantErr && store == nil {
				t.Fatal("expected store instance")
			}
		})
	}
}

func TestPutAndGetShard(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("test-shard-1")
	shardData := []byte("this is encrypted shard data")

	// Put shard
	err = store.PutShard(shardID, shardData)
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}

	// Verify shard file exists
	shardPath := filepath.Join(baseDir, shardID+".bin")
	if _, err := os.Stat(shardPath); err != nil {
		t.Fatalf("shard file not created at %s: %v", shardPath, err)
	}

	// Get shard
	retrieved, err := store.GetShard(shardID)
	if err != nil {
		t.Fatalf("GetShard failed: %v", err)
	}

	if !bytes.Equal(retrieved, shardData) {
		t.Fatal("retrieved shard data does not match original")
	}
}

func TestPutShardUpdatesIndex(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("shard-123")
	shardData := []byte("shard content")

	// Put shard
	err = store.PutShard(shardID, shardData)
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}

	// Verify index file exists
	indexPath := filepath.Join(baseDir, "shard-index.json")
	if _, err := os.Stat(indexPath); err != nil {
		t.Fatalf("index file not created at %s: %v", indexPath, err)
	}

	// Load and verify index content
	indexData, err := ioutil.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("failed to read index: %v", err)
	}

	var idx ShardIndex
	if err := json.Unmarshal(indexData, &idx); err != nil {
		t.Fatalf("failed to unmarshal index: %v", err)
	}

	if _, exists := idx.Shards[shardID]; !exists {
		t.Fatal("shard not in index")
	}

	if idx.Shards[shardID].Size != int64(len(shardData)) {
		t.Fatalf("index size mismatch: expected %d, got %d", len(shardData), idx.Shards[shardID].Size)
	}
}

func TestDeleteShard(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("shard-to-delete")
	shardData := []byte("temporary shard")

	// Put shard
	err = store.PutShard(shardID, shardData)
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}

	// Verify shard exists
	exists, err := store.HasShard(shardID)
	if err != nil {
		t.Fatalf("HasShard failed: %v", err)
	}
	if !exists {
		t.Fatal("shard should exist after PutShard")
	}

	// Delete shard
	err = store.DeleteShard(shardID)
	if err != nil {
		t.Fatalf("DeleteShard failed: %v", err)
	}

	// Verify shard is gone
	exists, err = store.HasShard(shardID)
	if err != nil {
		t.Fatalf("HasShard failed: %v", err)
	}
	if exists {
		t.Fatal("shard should not exist after DeleteShard")
	}

	// Verify shard file is deleted
	shardPath := filepath.Join(baseDir, shardID+".bin")
	if _, err := os.Stat(shardPath); err == nil {
		t.Fatal("shard file should be deleted")
	}
}

func TestListShards(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	// Add multiple shards
	shardIDs := []string{validShardID("shard1"), validShardID("shard2"), validShardID("shard3")}
	for _, id := range shardIDs {
		err := store.PutShard(id, []byte("data for "+id))
		if err != nil {
			t.Fatalf("PutShard failed: %v", err)
		}
	}

	// List shards
	listedIDs, err := store.ListShards()
	if err != nil {
		t.Fatalf("ListShards failed: %v", err)
	}

	if len(listedIDs) != len(shardIDs) {
		t.Fatalf("expected %d shards, got %d", len(shardIDs), len(listedIDs))
	}

	// Verify all shards are in list
	seen := make(map[string]bool)
	for _, id := range listedIDs {
		seen[id] = true
	}

	for _, expectedID := range shardIDs {
		if !seen[expectedID] {
			t.Fatalf("shard %s not found in list", expectedID)
		}
	}
}

func TestHasShard(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("existing-shard")

	// Check non-existent shard
	exists, err := store.HasShard(shardID)
	if err != nil {
		t.Fatalf("HasShard failed: %v", err)
	}
	if exists {
		t.Fatal("shard should not exist")
	}

	// Put shard
	err = store.PutShard(shardID, []byte("data"))
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}

	// Check existing shard
	exists, err = store.HasShard(shardID)
	if err != nil {
		t.Fatalf("HasShard failed: %v", err)
	}
	if !exists {
		t.Fatal("shard should exist")
	}
}

func TestIndexPersistence(t *testing.T) {
	baseDir := createTempDir(t)

	// Create store and add shards
	store1, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("persistent-shard")
	shardData := []byte("this should persist")

	err = store1.PutShard(shardID, shardData)
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}

	// Create new store instance from same directory
	store2, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	// Verify shard can be retrieved from new instance
	retrieved, err := store2.GetShard(shardID)
	if err != nil {
		t.Fatalf("GetShard failed: %v", err)
	}

	if !bytes.Equal(retrieved, shardData) {
		t.Fatal("persisted shard data does not match")
	}
}

func TestConcurrentPutGet(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	const numGoroutines = 10
	const shardsPerGoroutine = 5

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*shardsPerGoroutine)

	// Concurrent puts
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < shardsPerGoroutine; j++ {
				shardID := testShardID(workerID, j)
				shardData := []byte("data from worker " + testShardID(workerID, j))
				if err := store.PutShard(shardID, shardData); err != nil {
					errChan <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			t.Fatalf("concurrent put failed: %v", err)
		}
	}

	// Verify all shards can be retrieved
	listedIDs, err := store.ListShards()
	if err != nil {
		t.Fatalf("ListShards failed: %v", err)
	}

	if len(listedIDs) != numGoroutines*shardsPerGoroutine {
		t.Fatalf("expected %d shards, got %d", numGoroutines*shardsPerGoroutine, len(listedIDs))
	}

	// Concurrent gets
	errChan = make(chan error, numGoroutines*shardsPerGoroutine)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < shardsPerGoroutine; j++ {
				shardID := testShardID(workerID, j)
				data, err := store.GetShard(shardID)
				if err != nil {
					errChan <- err
					return
				}
				// Verify data
				expectedData := []byte("data from worker " + testShardID(workerID, j))
				if !bytes.Equal(data, expectedData) {
					errChan <- errors.New("shard data mismatch")
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			t.Fatalf("concurrent get failed: %v", err)
		}
	}
}

func TestErrorCases(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	tests := []struct {
		name    string
		fn      func() error
		wantErr bool
		errMsg  string
	}{
		{
			name:    "put with empty ID",
			fn:      func() error { return store.PutShard("", []byte("data")) },
			wantErr: true,
			errMsg:  "shard ID cannot be empty",
		},
		{
			name:    "put with empty data",
			fn:      func() error { return store.PutShard(validShardID("id"), []byte{}) },
			wantErr: true,
			errMsg:  "shard data cannot be empty",
		},
		{
			name:    "get non-existent shard",
			fn:      func() error { _, err := store.GetShard(validShardID("non-existent")); return err },
			wantErr: true,
		},
		{
			name:    "delete non-existent shard",
			fn:      func() error { return store.DeleteShard(validShardID("non-existent")) },
			wantErr: true,
		},
		{
			name:    "has shard empty ID",
			fn:      func() error { _, err := store.HasShard(""); return err },
			wantErr: true,
			errMsg:  "shard ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOverwriteShard(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("shard-to-overwrite")
	data1 := []byte("first version")
	data2 := []byte("second version - different data")

	// Put first version
	err = store.PutShard(shardID, data1)
	if err != nil {
		t.Fatalf("first PutShard failed: %v", err)
	}

	// Overwrite with second version
	err = store.PutShard(shardID, data2)
	if err != nil {
		t.Fatalf("second PutShard failed: %v", err)
	}

	// Verify latest version is returned
	retrieved, err := store.GetShard(shardID)
	if err != nil {
		t.Fatalf("GetShard failed: %v", err)
	}

	if !bytes.Equal(retrieved, data2) {
		t.Fatal("did not retrieve overwritten version")
	}

	// Verify shard list still has only one entry
	listedIDs, err := store.ListShards()
	if err != nil {
		t.Fatalf("ListShards failed: %v", err)
	}

	if len(listedIDs) != 1 {
		t.Fatalf("expected 1 shard, got %d", len(listedIDs))
	}
}

func TestGetStoreStats(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	// Empty store
	stats := store.GetStats()
	if stats.TotalShards != 0 {
		t.Fatalf("expected 0 shards, got %d", stats.TotalShards)
	}
	if stats.TotalSize != 0 {
		t.Fatalf("expected 0 bytes, got %d", stats.TotalSize)
	}

	// Add shards
	totalExpectedSize := int64(0)
	for i := 0; i < 3; i++ {
		data := []byte("shard data number " + string(rune(i)))
		err := store.PutShard(validShardID(fmt.Sprintf("shard%d", i)), data)
		if err != nil {
			t.Fatalf("PutShard failed: %v", err)
		}
		totalExpectedSize += int64(len(data))
	}

	// Verify stats
	stats = store.GetStats()
	if stats.TotalShards != 3 {
		t.Fatalf("expected 3 shards, got %d", stats.TotalShards)
	}
	if stats.TotalSize != totalExpectedSize {
		t.Fatalf("expected %d bytes, got %d", totalExpectedSize, stats.TotalSize)
	}
}

func TestGetShardMetadata(t *testing.T) {
	baseDir := createTempDir(t)
	store, err := NewLocalFileStore(baseDir)
	if err != nil {
		t.Fatalf("NewLocalFileStore failed: %v", err)
	}

	shardID := validShardID("shard-metadata-test")
	shardData := []byte("test data for metadata")

	// Put shard
	err = store.PutShard(shardID, shardData)
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}

	// Get metadata
	metadata, err := store.GetShardMetadata(shardID)
	if err != nil {
		t.Fatalf("GetShardMetadata failed: %v", err)
	}

	if metadata.Size != int64(len(shardData)) {
		t.Fatalf("size mismatch: expected %d, got %d", len(shardData), metadata.Size)
	}

	if metadata.Path == "" {
		t.Fatal("path should not be empty")
	}

	if metadata.CreatedAt == "" {
		t.Fatal("created at should not be empty")
	}

	// Non-existent shard
	_, err = store.GetShardMetadata("non-existent")
	if err == nil {
		t.Fatal("expected error for non-existent shard")
	}
}

// Helper function to generate test shard IDs
func testShardID(workerID, jobID int) string {
	return validShardID(fmt.Sprintf("shard-w%d-j%d", workerID, jobID))
}

// Benchmark operations
func BenchmarkPutShard(b *testing.B) {
	tmpDir := os.TempDir()
	store, _ := NewLocalFileStore(tmpDir)

	data := make([]byte, 1024*1024) // 1MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shardID := validShardID(fmt.Sprintf("bench-%d", i%100))
		store.PutShard(shardID, data)
	}
}

func BenchmarkGetShard(b *testing.B) {
	tmpDir := os.TempDir()
	store, _ := NewLocalFileStore(tmpDir)

	// Pre-populate with shards
	for i := 0; i < 10; i++ {
		data := make([]byte, 1024*1024)
		store.PutShard(validShardID(fmt.Sprintf("bench-%d", i)), data)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shardID := validShardID(fmt.Sprintf("bench-%d", i%10))
		store.GetShard(shardID)
	}
}
