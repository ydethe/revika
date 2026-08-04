package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiskStore persists shards as files under a root directory, fanned out by the
// first byte of the ID (…/root/ab/abcdef…). It is safe for concurrent use:
// writes go to a temp file and are atomically renamed into place, and content
// addressing makes concurrent writers of identical bytes harmless.
type DiskStore struct {
	root string
}

// NewDiskStore opens (creating if needed) a disk-backed store rooted at dir.
func NewDiskStore(dir string) (*DiskStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: create root: %w", err)
	}
	return &DiskStore{root: dir}, nil
}

var _ Store = (*DiskStore)(nil)

func (d *DiskStore) pathFor(id ShardID) (dir, file string) {
	name := id.String()
	dir = filepath.Join(d.root, name[:2])
	return dir, filepath.Join(dir, name)
}

func (d *DiskStore) Put(_ context.Context, data []byte) (ShardID, error) {
	id := HashOf(data)
	dir, file := d.pathFor(id)
	if _, err := os.Stat(file); err == nil {
		return id, nil // already present
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return id, fmt.Errorf("store: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return id, fmt.Errorf("store: temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return id, fmt.Errorf("store: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return id, fmt.Errorf("store: close: %w", err)
	}
	if err := os.Rename(tmpName, file); err != nil {
		os.Remove(tmpName)
		return id, fmt.Errorf("store: rename: %w", err)
	}
	return id, nil
}

// Get returns id's bytes, or ErrNotFound. It recomputes the hash of the stored
// bytes and returns ErrCorrupt if they no longer match the content address.
//
// Defence controls (security/Defence.md; primitive P5 in security/frameworks.md):
//   D3-FH (File Hashing) / SI-7 (…Information Integrity) — integrity re-check on every read.
func (d *DiskStore) Get(_ context.Context, id ShardID) ([]byte, error) {
	_, file := d.pathFor(id)
	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: read: %w", err)
	}
	if HashOf(data) != id {
		return nil, ErrCorrupt
	}
	return data, nil
}

func (d *DiskStore) Has(_ context.Context, id ShardID) (bool, error) {
	_, file := d.pathFor(id)
	_, err := os.Stat(file)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("store: stat: %w", err)
}

func (d *DiskStore) Delete(_ context.Context, id ShardID) error {
	_, file := d.pathFor(id)
	if err := os.Remove(file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("store: remove: %w", err)
	}
	return nil
}

var _ Lister = (*DiskStore)(nil)

// List walks the fan-out directories under the root and returns the ID of every
// shard file found. Entries that are not valid shard filenames (temp files, a
// stray directory) are skipped rather than erroring, so a partially-written or
// externally-touched store still enumerates cleanly.
func (d *DiskStore) List(_ context.Context) ([]ShardID, error) {
	dirs, err := os.ReadDir(d.root)
	if err != nil {
		return nil, fmt.Errorf("store: read root: %w", err)
	}
	var ids []ShardID
	for _, dir := range dirs {
		// Shards fan out into two-hex-char subdirectories (…/root/ab/abcd…).
		if !dir.IsDir() || len(dir.Name()) != 2 {
			continue
		}
		sub := filepath.Join(d.root, dir.Name())
		files, err := os.ReadDir(sub)
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", sub, err)
		}
		for _, f := range files {
			name := f.Name()
			if f.IsDir() || strings.HasPrefix(name, ".tmp-") {
				continue
			}
			raw, err := hex.DecodeString(name)
			if err != nil || len(raw) != len(ShardID{}) {
				continue
			}
			var id ShardID
			copy(id[:], raw)
			ids = append(ids, id)
		}
	}
	return ids, nil
}
