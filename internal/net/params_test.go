package net

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"

	"revika/internal/cap"
	"revika/internal/store"
)

// paramsNode builds a server host answering the params protocol. When d > 0 the
// node enforces proof-of-work admission under puzzle at d bits; d == 0 leaves it
// disabled. Returns the host to dial.
func paramsNode(t *testing.T, puzzle cap.Puzzle, d cap.Difficulty) host.Host {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	srv := NewServer(store.NewMemStore(), nil)
	srv.SetPoW(puzzle, d)
	srv.Register(h)
	return h
}

func TestQueryParamsRoundTrip(t *testing.T) {
	server := paramsNode(t, cap.DefaultArgon2id(), 9)
	client := clientHost(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := QueryParams(ctx, client, server.ID())
	if err != nil {
		t.Fatalf("QueryParams: %v", err)
	}
	want := PoWInfo{Enabled: true, Puzzle: "argon2id", Difficulty: 9}
	if got.PoW != want {
		t.Fatalf("QueryParams PoW = %+v, want %+v", got.PoW, want)
	}
}

// TestQueryParamsDisabled confirms a node enforcing no proof-of-work reports the
// policy as disabled (difficulty 0, no puzzle) rather than erroring.
func TestQueryParamsDisabled(t *testing.T) {
	server := paramsNode(t, nil, 0)
	client := clientHost(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := QueryParams(ctx, client, server.ID())
	if err != nil {
		t.Fatalf("QueryParams: %v", err)
	}
	if got.PoW != (PoWInfo{}) {
		t.Fatalf("QueryParams PoW = %+v, want disabled (zero)", got.PoW)
	}
}
