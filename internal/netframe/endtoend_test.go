package netframe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/revika/revika/internal/store"
)

var testSecret = []byte("end-to-end-secret")

// startServer spins up Serve on a loopback listener backed by a fresh in-memory store and
// returns a connected Client. Everything is torn down via t.Cleanup.
func startServer(t *testing.T, backend store.Store) *Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = Serve(ctx, listener, backend, testSecret)
	}()

	client, err := Dial(context.Background(), listener.Addr().String(), testSecret)
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		cancel()
		<-serveDone
	})
	return client
}

func TestEndToEndRoundTrip(t *testing.T) {
	client := startServer(t, store.NewMemory())
	ctx := context.Background()
	const id = store.ObjectID("object-1")
	payload := []byte("some opaque ciphertext bytes")

	if err := client.Put(ctx, id, bytes.NewReader(payload)); err != nil {
		t.Fatalf("put: %v", err)
	}

	present, err := client.Has(ctx, id)
	if err != nil {
		t.Fatalf("has: %v", err)
	}
	if !present {
		t.Fatal("expected object present after put")
	}

	reader, err := client.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}

	if err := client.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	present, err = client.Has(ctx, id)
	if err != nil {
		t.Fatalf("has after delete: %v", err)
	}
	if present {
		t.Fatal("expected object absent after delete")
	}
}

func TestEndToEndGetNotFound(t *testing.T) {
	client := startServer(t, store.NewMemory())
	_, err := client.Get(context.Background(), store.ObjectID("missing"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestEndToEndPutAlreadyExists(t *testing.T) {
	client := startServer(t, store.NewMemory())
	ctx := context.Background()
	const id = store.ObjectID("dup")
	if err := client.Put(ctx, id, bytes.NewReader([]byte("first"))); err != nil {
		t.Fatalf("first put: %v", err)
	}
	err := client.Put(ctx, id, bytes.NewReader([]byte("second")))
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestEndToEndDeleteNotFound(t *testing.T) {
	client := startServer(t, store.NewMemory())
	err := client.Delete(context.Background(), store.ObjectID("missing"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestEndToEndLargeObjectMultipleChunks(t *testing.T) {
	client := startServer(t, store.NewMemory())
	ctx := context.Background()
	const id = store.ObjectID("big")
	payload := bytes.Repeat([]byte("revika"), chunkSize) // spans several DATA frames

	if err := client.Put(ctx, id, bytes.NewReader(payload)); err != nil {
		t.Fatalf("put: %v", err)
	}
	reader, err := client.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large object mismatch: got %d bytes want %d", len(got), len(payload))
	}
}

func TestEndToEndConcurrentCallsSerialized(t *testing.T) {
	client := startServer(t, store.NewMemory())
	ctx := context.Background()

	// Seed distinct objects, then hammer the single connection from many goroutines. The
	// client mutex must serialize them without corrupting the shared stream.
	const count = 25
	for i := 0; i < count; i++ {
		id := store.ObjectID(fmt.Sprintf("obj-%d", i))
		if err := client.Put(ctx, id, bytes.NewReader([]byte(fmt.Sprintf("payload-%d", i)))); err != nil {
			t.Fatalf("seed put %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := store.ObjectID(fmt.Sprintf("obj-%d", i))
			reader, err := client.Get(ctx, id)
			if err != nil {
				errCh <- fmt.Errorf("get %d: %w", i, err)
				return
			}
			got, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				errCh <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			want := fmt.Sprintf("payload-%d", i)
			if string(got) != want {
				errCh <- fmt.Errorf("obj %d: got %q want %q", i, got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
