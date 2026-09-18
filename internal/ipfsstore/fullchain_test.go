package ipfsstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/revika/revika/internal/netframe"
	"github.com/revika/revika/internal/store"
)

// This file wires the whole out-of-process IPFS adapter stack together and drives it from a
// client, standing in for the deploy/ipfs docker-compose chain (client -> adapter -> kubo)
// so CI can exercise it under CGO_ENABLED=0 without a real Kubo node or the public IPFS
// network. The stack under test is:
//
//	netframe.Client  --rvk-plugin-v1 frames over TCP (Hop A)-->  netframe.Serve
//	                 --Kubo MFS HTTP RPC (Hop B)-->  ipfsstore.Store  -->  fakeKubo stub
//
// It is the same round-trip the revika-smoke binary performs, with the network replaced by
// the in-memory fakeKubo defined in ipfsstore_test.go.

var fullChainSecret = []byte("full-chain-shared-secret")

// startFullChain brings up the fakeKubo -> ipfsstore -> netframe.Serve stack on loopback and
// returns a connected client plus the backing fake. Everything is torn down via t.Cleanup.
func startFullChain(t *testing.T) (*netframe.Client, *fakeKubo) {
	t.Helper()

	// Hop B target: a stubbed Kubo node fronted by the real ipfsstore.Store.
	fake := newFakeKubo()
	kubo := httptest.NewServer(fake)
	t.Cleanup(kubo.Close)
	backend := New(kubo.URL, kubo.Client())

	// Hop A: the adapter server speaking the frame protocol in front of that store.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = netframe.Serve(ctx, listener, backend, fullChainSecret)
	}()

	client, err := netframe.Dial(context.Background(), listener.Addr().String(), fullChainSecret)
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		cancel()
		<-serveDone
	})
	return client, fake
}

// TestFullChainClientToKubo runs the revika-smoke round-trip (Put, Get with a byte check,
// Has, Delete, Has-absent) across every hop from the client down to the stubbed Kubo node,
// and checks that the bytes actually landed in the fake under an opaque, hashed identifier.
func TestFullChainClientToKubo(t *testing.T) {
	client, fake := startFullChain(t)
	ctx := context.Background()

	const id = store.ObjectID("smoke-test-object")
	payload := []byte("revika smoke-test ciphertext payload")

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
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("get returned different bytes than were put: got %q want %q", got, payload)
	}

	present, err := client.Has(ctx, id)
	if err != nil {
		t.Fatalf("has: %v", err)
	}
	if !present {
		t.Fatal("expected object present after put")
	}

	// Least knowledge: the object reached Kubo verbatim, keyed by a hashed MFS path that
	// never carries the raw ObjectID.
	fake.mu.Lock()
	stored, ok := fake.files[mfsPath(id)]
	leaks := false
	for path := range fake.files {
		if bytes.Contains([]byte(path), []byte(id)) {
			leaks = true
		}
	}
	fake.mu.Unlock()
	if !ok {
		t.Fatal("object not stored in fake kubo under its hashed path")
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("stored bytes differ from payload: got %q want %q", stored, payload)
	}
	if leaks {
		t.Fatal("kubo path leaks the raw object id")
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

// TestFullChainGetMissingNotFound confirms Kubo's "file does not exist" response is mapped to
// store.ErrNotFound and propagated back across the frame protocol to the client.
func TestFullChainGetMissingNotFound(t *testing.T) {
	client, _ := startFullChain(t)
	_, err := client.Get(context.Background(), store.ObjectID("missing"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestFullChainPutDuplicateAlreadyExists confirms the duplicate-object guard survives the
// full round-trip: a second Put of the same id reaches the client as store.ErrAlreadyExists.
func TestFullChainPutDuplicateAlreadyExists(t *testing.T) {
	client, _ := startFullChain(t)
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

// TestFullChainDeleteMissingNotFound confirms a delete of an absent object is reported as
// store.ErrNotFound end to end.
func TestFullChainDeleteMissingNotFound(t *testing.T) {
	client, _ := startFullChain(t)
	err := client.Delete(context.Background(), store.ObjectID("missing"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestFullChainLargeObject pushes a payload large enough to span many DATA frames on Hop A,
// exercising the client/server streaming and the ipfsstore multipart upload together.
func TestFullChainLargeObject(t *testing.T) {
	client, _ := startFullChain(t)
	ctx := context.Background()
	const id = store.ObjectID("big")
	payload := bytes.Repeat([]byte("revika-ciphertext"), 100_000) // ~1.7 MiB

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
