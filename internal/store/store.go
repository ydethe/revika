package store

// Package store provides storage backends for encrypted shards.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// shardIDPattern matches a valid shard ID: a hex-encoded SHA256 (64 lowercase hex chars).
var shardIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validateShardID rejects malformed shard IDs before they reach the filesystem,
// guarding against path traversal and invalid filename characters.
func validateShardID(id string) error {
	if id == "" {
		return errors.New("shard ID cannot be empty")
	}
	if !shardIDPattern.MatchString(id) {
		return errors.New("invalid shard ID")
	}
	return nil
}

// FileBackend defines the interface for shard storage.
// Implementations must be thread-safe for concurrent access.
type FileBackend interface {
	// PutShard stores an encrypted shard by ID.
	PutShard(id string, data []byte) error

	// GetShard retrieves an encrypted shard by ID.
	GetShard(id string) ([]byte, error)

	// DeleteShard removes a shard by ID.
	DeleteShard(id string) error

	// ListShards returns all shard IDs stored on this node.
	ListShards() ([]string, error)

	// HasShard checks if a shard with given ID exists.
	HasShard(id string) (bool, error)
}

// ShardIndexEntry represents a single shard in the index.
// It stores metadata about a persisted shard including its file path, size, and creation timestamp.
type ShardIndexEntry struct {
	Path      string `json:"path"`    // relative or absolute path to shard file
	Size      int64  `json:"size"`    // shard size in bytes
	CreatedAt string `json:"created"` // ISO 8601 timestamp
}

// ShardIndex represents the complete shard index file.
// It maps shard IDs to their metadata entries for efficient lookup during shard retrieval operations.
type ShardIndex struct {
	Shards map[string]ShardIndexEntry `json:"shards"`
}

// LocalFileStore is a file-based implementation of FileBackend.
// Stores shards as .bin files in baseDir and maintains a JSON index.
type LocalFileStore struct {
	baseDir   string // .revika/node-store/ or similar
	indexPath string // path to shard-index.json
	index     map[string]ShardIndexEntry
	mu        sync.RWMutex // protects index
}

// NewLocalFileStore creates a new LocalFileStore at the specified baseDir.
// Creates baseDir if it doesn't exist.
// Loads existing shard index if present.
func NewLocalFileStore(baseDir string) (*LocalFileStore, error) {
	if baseDir == "" {
		return nil, errors.New("baseDir cannot be empty")
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	store := &LocalFileStore{
		baseDir:   baseDir,
		indexPath: filepath.Join(baseDir, "shard-index.json"),
		index:     make(map[string]ShardIndexEntry),
	}

	// Load existing index if it exists
	if err := store.loadIndex(); err != nil {
		// If index doesn't exist, that's OK (new store)
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to load shard index: %w", err)
		}
	}

	return store, nil
}

// loadIndex loads the shard-index.json file from disk.
func (s *LocalFileStore) loadIndex() error {
	data, err := ioutil.ReadFile(s.indexPath)
	if err != nil {
		return err
	}

	var idx ShardIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return fmt.Errorf("failed to parse shard index: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.index = idx.Shards

	return nil
}

// saveIndex writes the shard-index.json file to disk.
// Must be called with lock held or in protected context.
func (s *LocalFileStore) saveIndex() error {
	idx := ShardIndex{Shards: s.index}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal shard index: %w", err)
	}

	// Write to temp file first, then rename (atomic operation)
	tempPath := s.indexPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write shard index: %w", err)
	}

	if err := os.Rename(tempPath, s.indexPath); err != nil {
		// Clean up temp file on error
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename shard index: %w", err)
	}

	return nil
}

// PutShard stores an encrypted shard by ID.
// Writes shard to .revika/node-store/{id}.bin and updates shard-index.json.
// Overwrites existing shard with same ID.
func (s *LocalFileStore) PutShard(id string, data []byte) error {
	if err := validateShardID(id); err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("shard data cannot be empty")
	}

	// Construct shard file path
	shardPath := filepath.Join(s.baseDir, id+".bin")

	// Write shard data to file
	if err := ioutil.WriteFile(shardPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write shard file: %w", err)
	}

	// Update index
	s.mu.Lock()
	defer s.mu.Unlock()

	s.index[id] = ShardIndexEntry{
		Path:      shardPath,
		Size:      int64(len(data)),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Persist index to disk
	if err := s.saveIndex(); err != nil {
		// Shard was written but index save failed - log this
		// In production, should handle recovery/rollback
		return fmt.Errorf("shard written but index save failed: %w", err)
	}

	return nil
}

// GetShard retrieves an encrypted shard by ID.
// Returns the shard data or error if not found.
func (s *LocalFileStore) GetShard(id string) ([]byte, error) {
	if err := validateShardID(id); err != nil {
		return nil, err
	}

	s.mu.RLock()
	entry, exists := s.index[id]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("shard %s not found", id)
	}

	// Read shard file
	data, err := ioutil.ReadFile(entry.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read shard file: %w", err)
	}

	return data, nil
}

// DeleteShard removes a shard by ID.
// Deletes shard file and updates shard-index.json.
func (s *LocalFileStore) DeleteShard(id string) error {
	if err := validateShardID(id); err != nil {
		return err
	}

	s.mu.Lock()
	entry, exists := s.index[id]
	s.mu.Unlock()

	if !exists {
		return fmt.Errorf("shard %s not found", id)
	}

	// Delete shard file
	if err := os.Remove(entry.Path); err != nil {
		// If file doesn't exist, continue with index cleanup
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to delete shard file: %w", err)
		}
	}

	// Update index
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.index, id)

	// Persist index to disk
	if err := s.saveIndex(); err != nil {
		return fmt.Errorf("shard deleted but index save failed: %w", err)
	}

	return nil
}

// ListShards returns all shard IDs stored on this node.
func (s *LocalFileStore) ListShards() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.index))
	for id := range s.index {
		ids = append(ids, id)
	}

	return ids, nil
}

// HasShard checks if a shard with given ID exists.
func (s *LocalFileStore) HasShard(id string) (bool, error) {
	if err := validateShardID(id); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.index[id]
	return exists, nil
}

// GetShardMetadata returns metadata for a shard without loading its data.
func (s *LocalFileStore) GetShardMetadata(id string) (ShardIndexEntry, error) {
	if id == "" {
		return ShardIndexEntry{}, errors.New("shard ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.index[id]
	if !exists {
		return ShardIndexEntry{}, fmt.Errorf("shard %s not found", id)
	}

	return entry, nil
}

// StoreStats holds statistics about the shard store.
// It provides information about the number of stored shards, total storage size, and directory paths.
type StoreStats struct {
	TotalShards int64  // number of shards stored
	TotalSize   int64  // total size in bytes of all shards
	IndexPath   string // path to the shard index file
	BaseDir     string // base directory for shard storage
}

// GetStats returns statistics about the store.
func (s *LocalFileStore) GetStats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalSize int64
	for _, entry := range s.index {
		totalSize += entry.Size
	}

	return StoreStats{
		TotalShards: int64(len(s.index)),
		TotalSize:   totalSize,
		IndexPath:   s.indexPath,
		BaseDir:     s.baseDir,
	}
}
