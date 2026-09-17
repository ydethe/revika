package store

import (
	"bytes"
	"context"
	"io"
	"sync"
)

type Memory struct {
	mu      sync.RWMutex
	objects map[ObjectID][]byte
}

func NewMemory() *Memory {
	return &Memory{objects: make(map[ObjectID][]byte)}
}

func (s *Memory) Put(ctx context.Context, id ObjectID, content io.Reader) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[id]; exists {
		return ErrAlreadyExists
	}
	s.objects[id] = append([]byte(nil), data...)
	return nil
}

func (s *Memory) Get(ctx context.Context, id ObjectID) (io.ReadCloser, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	data, exists := s.objects[id]
	copyData := append([]byte(nil), data...)
	s.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(copyData)), nil
}

func (s *Memory) Has(ctx context.Context, id ObjectID) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	s.mu.RLock()
	_, exists := s.objects[id]
	s.mu.RUnlock()
	return exists, nil
}

func (s *Memory) Delete(ctx context.Context, id ObjectID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[id]; !exists {
		return ErrNotFound
	}
	delete(s.objects, id)
	return nil
}

func (s *Memory) Close() error { return nil }
