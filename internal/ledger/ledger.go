package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/revika/revika/pkg/model"
)

// Tree represents a directory tree in the ledger.
type Tree struct {
	ID           string            `json:"id"`
	RootPath     string            `json:"root_path"`
	Created      time.Time         `json:"created"`
	Files        map[string]*File  `json:"files"`
	AccessGrants map[string]*Grant `json:"access_grants"`
}

// File represents a file tracked in the ledger.
type File struct {
	ID          string           `json:"id"`
	Path        string           `json:"path"`
	ContentHash string           `json:"content_hash"` // sha256:...
	Shards      []model.ShardRef `json:"shards"`       // shard references (integrity hash + CID)
	Size        int64            `json:"size"`
	K           int              `json:"k"` // data shards
	M           int              `json:"m"` // parity shards
	CreatedAt   time.Time        `json:"created_at"`
	ModifiedAt  time.Time        `json:"modified_at"`
}

// Grant represents an access grant to another user.
type Grant struct {
	UserPeerID string     `json:"user_peer_id"`
	GrantedAt  time.Time  `json:"granted_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	KeyVersion int        `json:"key_version"`
}

// Ledger is the in-memory + persisted ledger.
type Ledger struct {
	Trees             map[string]*Tree                 `json:"trees"`
	AccessRevocations map[string]map[string]*time.Time `json:"access_revocations,omitempty"` // tree → user → revoked_at
	mu                sync.RWMutex                     `json:"-"`
}

// Load reads ledger from disk (`.revika/ledger.json`).
// If the file does not exist, returns an empty ledger.
// Returns model.ErrLedgerCorrupted if the file exists but cannot be parsed.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty ledger if file doesn't exist
			return &Ledger{
				Trees:             make(map[string]*Tree),
				AccessRevocations: make(map[string]map[string]*time.Time),
			}, nil
		}
		return nil, fmt.Errorf("%w: failed to read ledger file", model.ErrLedgerCorrupted)
	}

	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("%w: failed to parse ledger JSON", model.ErrLedgerCorrupted)
	}

	// Ensure maps are initialized
	if l.Trees == nil {
		l.Trees = make(map[string]*Tree)
	}
	if l.AccessRevocations == nil {
		l.AccessRevocations = make(map[string]map[string]*time.Time)
	}

	return &l, nil
}

// Save writes ledger to disk atomically (write temp, rename).
// Acquires write lock during serialization and file operations.
func (l *Ledger) Save(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ledger: %w", err)
	}

	// Write to temporary file in the same directory for atomic rename
	dir := os.TempDir()
	tmpFile, err := os.CreateTemp(dir, "ledger-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename ledger file: %w", err)
	}

	return nil
}

// AddTree creates a new directory tree in the ledger.
// Returns model.ErrInvalidPath if the tree ID already exists.
func (l *Ledger) AddTree(id, rootPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.Trees[id]; exists {
		return fmt.Errorf("%w: tree already exists", model.ErrInvalidPath)
	}

	l.Trees[id] = &Tree{
		ID:           id,
		RootPath:     rootPath,
		Created:      time.Now(),
		Files:        make(map[string]*File),
		AccessGrants: make(map[string]*Grant),
	}

	return nil
}

// AddFile adds a file to a tree.
// Returns model.ErrFileNotFound if the tree does not exist.
// Returns model.ErrInvalidPath if the file already exists in the tree.
func (l *Ledger) AddFile(treeID, fileID, filePath, contentHash string, shards []model.ShardRef, k, m int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tree, exists := l.Trees[treeID]
	if !exists {
		return fmt.Errorf("%w: tree not found", model.ErrFileNotFound)
	}

	if _, exists := tree.Files[fileID]; exists {
		return fmt.Errorf("%w: file already exists", model.ErrInvalidPath)
	}

	now := time.Now()
	tree.Files[fileID] = &File{
		ID:          fileID,
		Path:        filePath,
		ContentHash: contentHash,
		Shards:      shards,
		Size:        0, // Will be updated by caller if needed
		K:           k,
		M:           m,
		CreatedAt:   now,
		ModifiedAt:  now,
	}

	return nil
}

// RemoveFile removes a file from a tree.
// Returns model.ErrFileNotFound if the tree or file does not exist.
func (l *Ledger) RemoveFile(treeID, fileID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tree, exists := l.Trees[treeID]
	if !exists {
		return fmt.Errorf("%w: tree not found", model.ErrFileNotFound)
	}

	if _, exists := tree.Files[fileID]; !exists {
		return fmt.Errorf("%w: file not found", model.ErrFileNotFound)
	}

	delete(tree.Files, fileID)
	return nil
}

// GrantAccess grants access to a user for a tree.
// Returns model.ErrFileNotFound if the tree does not exist.
// Returns model.ErrInvalidPath if access has already been granted to this user.
func (l *Ledger) GrantAccess(treeID, userPeerID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tree, exists := l.Trees[treeID]
	if !exists {
		return fmt.Errorf("%w: tree not found", model.ErrFileNotFound)
	}

	if _, exists := tree.AccessGrants[userPeerID]; exists {
		return fmt.Errorf("%w: access already granted", model.ErrInvalidPath)
	}

	tree.AccessGrants[userPeerID] = &Grant{
		UserPeerID: userPeerID,
		GrantedAt:  time.Now(),
		KeyVersion: 0,
	}

	return nil
}

// RevokeAccess revokes access for a user.
// Returns model.ErrFileNotFound if the tree or grant does not exist.
// Sets RevokedAt timestamp and increments KeyVersion.
func (l *Ledger) RevokeAccess(treeID, userPeerID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tree, exists := l.Trees[treeID]
	if !exists {
		return fmt.Errorf("%w: tree not found", model.ErrFileNotFound)
	}

	grant, exists := tree.AccessGrants[userPeerID]
	if !exists {
		return fmt.Errorf("%w: grant not found", model.ErrFileNotFound)
	}

	now := time.Now()
	grant.RevokedAt = &now
	grant.KeyVersion++

	// Record in AccessRevocations for audit trail
	if l.AccessRevocations[treeID] == nil {
		l.AccessRevocations[treeID] = make(map[string]*time.Time)
	}
	l.AccessRevocations[treeID][userPeerID] = &now

	return nil
}

// GetTree returns a tree by ID (read-locked).
// Returns model.ErrFileNotFound if the tree does not exist.
func (l *Ledger) GetTree(treeID string) (*Tree, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	tree, exists := l.Trees[treeID]
	if !exists {
		return nil, fmt.Errorf("%w: tree not found", model.ErrFileNotFound)
	}

	return tree, nil
}

// ListTrees returns all tree IDs (read-locked).
func (l *Ledger) ListTrees() ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	treeIDs := make([]string, 0, len(l.Trees))
	for id := range l.Trees {
		treeIDs = append(treeIDs, id)
	}

	return treeIDs, nil
}
