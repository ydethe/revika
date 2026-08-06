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

// bootstrapAddr returns a dialable multiaddr (with /p2p/<id>) for h, the form a
// joining node passes to FetchPoWPolicy via -bootstrap.
func bootstrapAddr(t *testing.T, h host.Host) string {
	t.Helper()
	addrs := h.Addrs()
	if len(addrs) == 0 {
		t.Fatalf("host %s has no listen addresses", h.ID())
	}
	return addrs[0].String() + "/p2p/" + h.ID().String()
}

// freshHost is a bare dialing host (no pre-established connections), so
// FetchPoWPolicy exercises its own connect path.
func freshHost(t *testing.T) host.Host {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// TestFetchPoWPolicyStrictestWins reconciles two reachable nodes agreeing on the
// puzzle but at different difficulties: the joiner must satisfy the strictest, so
// it adopts the max difficulty.
func TestFetchPoWPolicyStrictestWins(t *testing.T) {
	easy := paramsNode(t, cap.DefaultArgon2id(), 8)
	hard := paramsNode(t, cap.DefaultArgon2id(), 14)
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	puzzle, diff, err := FetchPoWPolicy(ctx, client, []string{bootstrapAddr(t, easy), bootstrapAddr(t, hard)}, 10*time.Second)
	if err != nil {
		t.Fatalf("FetchPoWPolicy: %v", err)
	}
	if puzzle != "argon2id" || diff != 14 {
		t.Fatalf("FetchPoWPolicy = (%q, %d), want (argon2id, 14)", puzzle, diff)
	}
}

// TestFetchPoWPolicyPuzzleDisagreement rejects a node set whose PoW-enforcing
// members demand different puzzles: one self-certifying identity cannot satisfy
// both, so there is no policy to adopt.
func TestFetchPoWPolicyPuzzleDisagreement(t *testing.T) {
	argon := paramsNode(t, cap.DefaultArgon2id(), 10)
	sha := paramsNode(t, cap.SHA256Puzzle{}, 10)
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, _, err := FetchPoWPolicy(ctx, client, []string{bootstrapAddr(t, argon), bootstrapAddr(t, sha)}, 10*time.Second); err == nil {
		t.Fatal("FetchPoWPolicy: want error on puzzle disagreement, got nil")
	}
}

// TestFetchPoWPolicyAllDisabled confirms that when every reachable node enforces
// no proof-of-work, the joiner adopts an empty policy (no puzzle, zero
// difficulty) rather than erroring.
func TestFetchPoWPolicyAllDisabled(t *testing.T) {
	a := paramsNode(t, nil, 0)
	b := paramsNode(t, nil, 0)
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	puzzle, diff, err := FetchPoWPolicy(ctx, client, []string{bootstrapAddr(t, a), bootstrapAddr(t, b)}, 10*time.Second)
	if err != nil {
		t.Fatalf("FetchPoWPolicy: %v", err)
	}
	if puzzle != "" || diff != 0 {
		t.Fatalf("FetchPoWPolicy = (%q, %d), want (\"\", 0)", puzzle, diff)
	}
}

// TestFetchPoWPolicyNoneReachable fails closed: with no bootstrap node answering,
// an adopted policy could only be an offline guess, so the joiner must error.
func TestFetchPoWPolicyNoneReachable(t *testing.T) {
	// A well-formed multiaddr whose peer no host is listening for.
	unreachable := "/ip4/127.0.0.1/tcp/1/p2p/" + paramsNode(t, nil, 0).ID().String()
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, _, err := FetchPoWPolicy(ctx, client, []string{unreachable}, 2*time.Second); err == nil {
		t.Fatal("FetchPoWPolicy: want error when no bootstrap node is reachable, got nil")
	}
}
