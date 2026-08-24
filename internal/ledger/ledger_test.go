package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/revika/revika/pkg/model"
)

func TestLoad_FileNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "nonexistent.json")

	l, err := Load(ledgerPath)
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got: %v", err)
	}

	if l == nil || len(l.Trees) != 0 || len(l.AccessRevocations) != 0 {
		t.Errorf("expected empty ledger, got: %+v", l)
	}
}

func TestLoad_CorruptedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	err := os.WriteFile(ledgerPath, []byte("{ invalid json"), 0o600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	l, err := Load(ledgerPath)
	if err == nil || !errors.Is(err, model.ErrLedgerCorrupted) {
		t.Errorf("expected ErrLedgerCorrupted, got: %v", err)
	}
	if l != nil {
		t.Errorf("expected nil ledger on error, got: %+v", l)
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	// Create and save a ledger
	l := &Ledger{
		Trees:             make(map[string]*Tree),
		AccessRevocations: make(map[string]map[string]*time.Time),
	}

	l.AddTree("tree1", "/data")
	l.AddFile("tree1", "file1", "/data/file.txt", "sha256:abc", []model.ShardRef{{Hash: "shard1"}, {Hash: "shard2"}}, 2, 1)

	if err := l.Save(ledgerPath); err != nil {
		t.Fatalf("failed to save ledger: %v", err)
	}

	// Load and verify
	l2, err := Load(ledgerPath)
	if err != nil {
		t.Fatalf("failed to load ledger: %v", err)
	}

	if len(l2.Trees) != 1 {
		t.Errorf("expected 1 tree, got %d", len(l2.Trees))
	}

	tree, _ := l2.GetTree("tree1")
	if tree == nil {
		t.Fatalf("tree not found")
	}

	if len(tree.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(tree.Files))
	}
}

func TestAddTree(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		rootPath string
		wantErr  bool
		errType  error
		preExist bool
	}{
		{
			name:     "successful add",
			id:       "tree1",
			rootPath: "/data",
			wantErr:  false,
		},
		{
			name:     "tree already exists",
			id:       "tree1",
			rootPath: "/data",
			wantErr:  true,
			errType:  model.ErrInvalidPath,
			preExist: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Ledger{
				Trees:             make(map[string]*Tree),
				AccessRevocations: make(map[string]map[string]*time.Time),
			}

			if tt.preExist {
				l.AddTree(tt.id, tt.rootPath)
			}

			err := l.AddTree(tt.id, tt.rootPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !errors.Is(err, tt.errType) {
				t.Errorf("expected %v, got %v", tt.errType, err)
			}

			if !tt.wantErr || !tt.preExist {
				tree, exists := l.Trees[tt.id]
				if !exists {
					t.Errorf("tree not found after add")
					return
				}
				if tree.RootPath != tt.rootPath {
					t.Errorf("expected rootPath %q, got %q", tt.rootPath, tree.RootPath)
				}
			}
		})
	}
}

func TestAddFile(t *testing.T) {
	tests := []struct {
		name     string
		treeID   string
		fileID   string
		filePath string
		wantErr  bool
		errType  error
		setup    func(*Ledger)
	}{
		{
			name:     "successful add",
			treeID:   "tree1",
			fileID:   "file1",
			filePath: "/data/file.txt",
			wantErr:  false,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
			},
		},
		{
			name:     "tree not found",
			treeID:   "nonexistent",
			fileID:   "file1",
			filePath: "/data/file.txt",
			wantErr:  true,
			errType:  model.ErrFileNotFound,
			setup:    func(l *Ledger) {},
		},
		{
			name:     "file already exists",
			treeID:   "tree1",
			fileID:   "file1",
			filePath: "/data/file.txt",
			wantErr:  true,
			errType:  model.ErrInvalidPath,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
				l.AddFile("tree1", "file1", "/data/file.txt", "sha256:abc", []model.ShardRef{{Hash: "shard1"}}, 1, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Ledger{
				Trees:             make(map[string]*Tree),
				AccessRevocations: make(map[string]map[string]*time.Time),
			}
			tt.setup(l)

			err := l.AddFile(tt.treeID, tt.fileID, tt.filePath, "sha256:abc", []model.ShardRef{{Hash: "shard1"}}, 1, 1)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !errors.Is(err, tt.errType) {
				t.Errorf("expected %v, got %v", tt.errType, err)
			}

			if !tt.wantErr {
				tree, _ := l.GetTree(tt.treeID)
				file, exists := tree.Files[tt.fileID]
				if !exists {
					t.Errorf("file not found after add")
					return
				}
				if file.Path != tt.filePath {
					t.Errorf("expected path %q, got %q", tt.filePath, file.Path)
				}
			}
		})
	}
}

func TestRemoveFile(t *testing.T) {
	tests := []struct {
		name    string
		treeID  string
		fileID  string
		wantErr bool
		errType error
		setup   func(*Ledger)
	}{
		{
			name:    "successful remove",
			treeID:  "tree1",
			fileID:  "file1",
			wantErr: false,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
				l.AddFile("tree1", "file1", "/data/file.txt", "sha256:abc", []model.ShardRef{{Hash: "shard1"}}, 1, 1)
			},
		},
		{
			name:    "tree not found",
			treeID:  "nonexistent",
			fileID:  "file1",
			wantErr: true,
			errType: model.ErrFileNotFound,
			setup:   func(l *Ledger) {},
		},
		{
			name:    "file not found",
			treeID:  "tree1",
			fileID:  "nonexistent",
			wantErr: true,
			errType: model.ErrFileNotFound,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Ledger{
				Trees:             make(map[string]*Tree),
				AccessRevocations: make(map[string]map[string]*time.Time),
			}
			tt.setup(l)

			err := l.RemoveFile(tt.treeID, tt.fileID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoveFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !errors.Is(err, tt.errType) {
				t.Errorf("expected %v, got %v", tt.errType, err)
			}

			if !tt.wantErr {
				tree, _ := l.GetTree(tt.treeID)
				_, exists := tree.Files[tt.fileID]
				if exists {
					t.Errorf("file still exists after remove")
				}
			}
		})
	}
}

func TestGrantAccess(t *testing.T) {
	tests := []struct {
		name    string
		treeID  string
		userID  string
		wantErr bool
		errType error
		setup   func(*Ledger)
	}{
		{
			name:    "successful grant",
			treeID:  "tree1",
			userID:  "user1",
			wantErr: false,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
			},
		},
		{
			name:    "tree not found",
			treeID:  "nonexistent",
			userID:  "user1",
			wantErr: true,
			errType: model.ErrFileNotFound,
			setup:   func(l *Ledger) {},
		},
		{
			name:    "access already granted",
			treeID:  "tree1",
			userID:  "user1",
			wantErr: true,
			errType: model.ErrInvalidPath,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
				l.GrantAccess("tree1", "user1")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Ledger{
				Trees:             make(map[string]*Tree),
				AccessRevocations: make(map[string]map[string]*time.Time),
			}
			tt.setup(l)

			err := l.GrantAccess(tt.treeID, tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GrantAccess() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !errors.Is(err, tt.errType) {
				t.Errorf("expected %v, got %v", tt.errType, err)
			}

			if !tt.wantErr {
				tree, _ := l.GetTree(tt.treeID)
				grant, exists := tree.AccessGrants[tt.userID]
				if !exists {
					t.Errorf("grant not found after add")
					return
				}
				if grant.UserPeerID != tt.userID {
					t.Errorf("expected userID %q, got %q", tt.userID, grant.UserPeerID)
				}
				if grant.RevokedAt != nil {
					t.Errorf("expected RevokedAt to be nil for new grant")
				}
			}
		})
	}
}

func TestRevokeAccess(t *testing.T) {
	tests := []struct {
		name    string
		treeID  string
		userID  string
		wantErr bool
		errType error
		setup   func(*Ledger)
	}{
		{
			name:    "successful revoke",
			treeID:  "tree1",
			userID:  "user1",
			wantErr: false,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
				l.GrantAccess("tree1", "user1")
			},
		},
		{
			name:    "tree not found",
			treeID:  "nonexistent",
			userID:  "user1",
			wantErr: true,
			errType: model.ErrFileNotFound,
			setup:   func(l *Ledger) {},
		},
		{
			name:    "grant not found",
			treeID:  "tree1",
			userID:  "user2",
			wantErr: true,
			errType: model.ErrFileNotFound,
			setup: func(l *Ledger) {
				l.AddTree("tree1", "/data")
				l.GrantAccess("tree1", "user1")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Ledger{
				Trees:             make(map[string]*Tree),
				AccessRevocations: make(map[string]map[string]*time.Time),
			}
			tt.setup(l)

			err := l.RevokeAccess(tt.treeID, tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RevokeAccess() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !errors.Is(err, tt.errType) {
				t.Errorf("expected %v, got %v", tt.errType, err)
			}

			if !tt.wantErr {
				tree, _ := l.GetTree(tt.treeID)
				grant, exists := tree.AccessGrants[tt.userID]
				if !exists {
					t.Errorf("grant not found after revoke")
					return
				}
				if grant.RevokedAt == nil {
					t.Errorf("expected RevokedAt to be set after revoke")
				}
				if grant.KeyVersion != 1 {
					t.Errorf("expected KeyVersion to be 1 after revoke, got %d", grant.KeyVersion)
				}
			}
		})
	}
}

func TestGetTree(t *testing.T) {
	l := &Ledger{
		Trees:             make(map[string]*Tree),
		AccessRevocations: make(map[string]map[string]*time.Time),
	}
	l.AddTree("tree1", "/data")

	tests := []struct {
		name    string
		treeID  string
		wantErr bool
		errType error
	}{
		{
			name:    "tree found",
			treeID:  "tree1",
			wantErr: false,
		},
		{
			name:    "tree not found",
			treeID:  "nonexistent",
			wantErr: true,
			errType: model.ErrFileNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := l.GetTree(tt.treeID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !errors.Is(err, tt.errType) {
				t.Errorf("expected %v, got %v", tt.errType, err)
			}

			if !tt.wantErr && tree == nil {
				t.Errorf("expected non-nil tree")
			}
		})
	}
}

func TestListTrees(t *testing.T) {
	l := &Ledger{
		Trees:             make(map[string]*Tree),
		AccessRevocations: make(map[string]map[string]*time.Time),
	}

	// Empty ledger
	treeIDs, err := l.ListTrees()
	if err != nil {
		t.Errorf("ListTrees() error = %v", err)
	}
	if len(treeIDs) != 0 {
		t.Errorf("expected 0 trees, got %d", len(treeIDs))
	}

	// Add trees
	l.AddTree("tree1", "/data1")
	l.AddTree("tree2", "/data2")
	l.AddTree("tree3", "/data3")

	treeIDs, err = l.ListTrees()
	if err != nil {
		t.Errorf("ListTrees() error = %v", err)
	}
	if len(treeIDs) != 3 {
		t.Errorf("expected 3 trees, got %d", len(treeIDs))
	}

	// Verify all IDs are present
	idMap := make(map[string]bool)
	for _, id := range treeIDs {
		idMap[id] = true
	}

	for _, expected := range []string{"tree1", "tree2", "tree3"} {
		if !idMap[expected] {
			t.Errorf("expected tree %q not found in results", expected)
		}
	}
}

func TestConcurrency(t *testing.T) {
	l := &Ledger{
		Trees:             make(map[string]*Tree),
		AccessRevocations: make(map[string]map[string]*time.Time),
	}
	l.AddTree("tree1", "/data")

	// Concurrent reads and writes
	done := make(chan error, 10)

	// Writers
	for i := 0; i < 5; i++ {
		go func(i int) {
			fileID := "file" + string(rune(i))
			err := l.AddFile("tree1", fileID, "/data/"+fileID, "sha256:abc", []model.ShardRef{{Hash: "shard1"}}, 1, 1)
			done <- err
		}(i)
	}

	// Readers
	for i := 0; i < 5; i++ {
		go func() {
			_, err := l.ListTrees()
			done <- err
		}()
	}

	// Collect results
	for i := 0; i < 10; i++ {
		err := <-done
		if err != nil {
			t.Errorf("concurrent operation failed: %v", err)
		}
	}

	// Verify final state
	tree, _ := l.GetTree("tree1")
	if len(tree.Files) != 5 {
		t.Errorf("expected 5 files after concurrent adds, got %d", len(tree.Files))
	}
}
