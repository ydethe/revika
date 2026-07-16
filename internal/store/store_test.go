package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// runStoreSuite is the shared conformance suite; every Store implementation
// must pass it. newStore returns a fresh, empty store.
func runStoreSuite(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()

	t.Run("PutGetRoundTrip", func(t *testing.T) {
		s := newStore(t)
		data := []byte("hello revika")
		id, err := s.Put(ctx, data)
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round trip mismatch: got %q want %q", got, data)
		}
	})

	t.Run("IDIsContentAddress", func(t *testing.T) {
		s := newStore(t)
		data := []byte("content addressing")
		id, err := s.Put(ctx, data)
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		if id != HashOf(data) {
			t.Fatalf("id %s != HashOf(data) %s", id, HashOf(data))
		}
	})

	t.Run("PutIsIdempotent", func(t *testing.T) {
		s := newStore(t)
		data := []byte("same bytes")
		id1, _ := s.Put(ctx, data)
		id2, err := s.Put(ctx, data)
		if err != nil {
			t.Fatalf("second Put: %v", err)
		}
		if id1 != id2 {
			t.Fatalf("idempotent Put returned different IDs: %s vs %s", id1, id2)
		}
	})

	t.Run("Has", func(t *testing.T) {
		s := newStore(t)
		id, _ := s.Put(ctx, []byte("present"))
		if ok, err := s.Has(ctx, id); err != nil || !ok {
			t.Fatalf("Has(present) = %v, %v; want true, nil", ok, err)
		}
		if ok, err := s.Has(ctx, HashOf([]byte("absent"))); err != nil || ok {
			t.Fatalf("Has(absent) = %v, %v; want false, nil", ok, err)
		}
	})

	t.Run("GetMissingIsErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.Get(ctx, HashOf([]byte("nope")))
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get missing: got %v, want ErrNotFound", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s := newStore(t)
		id, _ := s.Put(ctx, []byte("temp"))
		if err := s.Delete(ctx, id); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if ok, _ := s.Has(ctx, id); ok {
			t.Fatal("shard still present after Delete")
		}
		if err := s.Delete(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Delete absent: got %v, want ErrNotFound", err)
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		s := newStore(t)
		id, err := s.Put(ctx, []byte{})
		if err != nil {
			t.Fatalf("Put empty: %v", err)
		}
		got, err := s.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get empty: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty, got %d bytes", len(got))
		}
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		s := newStore(t)
		const n = 64
		ids := make([]ShardID, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id, err := s.Put(ctx, []byte(fmt.Sprintf("blob-%d", i)))
				if err != nil {
					t.Errorf("concurrent Put: %v", err)
				}
				ids[i] = id
			}(i)
		}
		wg.Wait()
		for i := 0; i < n; i++ {
			got, err := s.Get(ctx, ids[i])
			if err != nil {
				t.Fatalf("Get %d: %v", i, err)
			}
			if want := fmt.Sprintf("blob-%d", i); string(got) != want {
				t.Fatalf("blob %d: got %q want %q", i, got, want)
			}
		}
	})
}

func TestMemStore(t *testing.T) {
	runStoreSuite(t, func(t *testing.T) Store { return NewMemStore() })
}

func TestDiskStore(t *testing.T) {
	runStoreSuite(t, func(t *testing.T) Store {
		s, err := NewDiskStore(t.TempDir())
		if err != nil {
			t.Fatalf("NewDiskStore: %v", err)
		}
		return s
	})
}

// TestDiskStoreDetectsCorruption is disk-specific: a Store must never hand back
// bytes that do not match their content address.
func TestDiskStoreDetectsCorruption(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	id, _ := s.Put(ctx, []byte("trust but verify"))

	// Corrupt the on-disk file behind the shard's back.
	_, file := s.pathFor(id)
	if err := os.WriteFile(file, []byte("tampered payload!!"), 0o644); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get corrupted shard: got %v, want ErrCorrupt", err)
	}
}

// TestDiskStorePrefixLayout documents the fan-out layout so a change to it is a
// deliberate decision, not an accident.
func TestDiskStorePrefixLayout(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	id, _ := s.Put(context.Background(), []byte("layout"))
	dir, file := s.pathFor(id)
	if filepath.Base(dir) != id.String()[:2] {
		t.Fatalf("prefix dir = %s, want %s", filepath.Base(dir), id.String()[:2])
	}
	if filepath.Base(file) != id.String() {
		t.Fatalf("file name = %s, want %s", filepath.Base(file), id.String())
	}
}
