package store

import (
	"context"
	"sync"
)

// MemStore is an in-memory Store, primarily for tests and the development
// "mock store". It is safe for concurrent use.
type MemStore struct {
	mu    sync.RWMutex
	blobs map[ShardID][]byte
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{blobs: make(map[ShardID][]byte)}
}

var _ Store = (*MemStore)(nil)

func (m *MemStore) Put(_ context.Context, data []byte) (ShardID, error) {
	id := HashOf(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[id]; !ok {
		// Copy so later mutation of the caller's slice cannot corrupt us.
		cp := make([]byte, len(data))
		copy(cp, data)
		m.blobs[id] = cp
	}
	return id, nil
}

func (m *MemStore) Get(_ context.Context, id ShardID) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func (m *MemStore) Has(_ context.Context, id ShardID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blobs[id]
	return ok, nil
}

func (m *MemStore) Delete(_ context.Context, id ShardID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[id]; !ok {
		return ErrNotFound
	}
	delete(m.blobs, id)
	return nil
}
