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
func paramsNode(t *testing.T, puzzle cap.Argon2idPuzzle, d cap.Difficulty) host.Host {
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
	want := PoWInfo{Enabled: true, Difficulty: 9}
	if got.PoW != want {
		t.Fatalf("QueryParams PoW = %+v, want %+v", got.PoW, want)
	}
}

// TestQueryParamsDisabled confirms a node enforcing no proof-of-work reports the
// policy as disabled (difficulty 0, no puzzle) rather than erroring.
func TestQueryParamsDisabled(t *testing.T) {
	server := paramsNode(t, cap.Argon2idPuzzle{}, 0)
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
	np, err := FetchNodePolicy(ctx, client, []string{bootstrapAddr(t, easy), bootstrapAddr(t, hard)}, 10*time.Second)
	if err != nil {
		t.Fatalf("FetchNodePolicy: %v", err)
	}
	if !np.PoW.Enabled || np.PoW.Difficulty != 14 {
		t.Fatalf("FetchNodePolicy PoW = %+v, want enabled at difficulty 14", np.PoW)
	}
}

// TestFetchPoWPolicyAllDisabled confirms that when every reachable node enforces
// no proof-of-work, the joiner adopts an empty policy (no puzzle, zero
// difficulty) rather than erroring.
func TestFetchPoWPolicyAllDisabled(t *testing.T) {
	a := paramsNode(t, cap.Argon2idPuzzle{}, 0)
	b := paramsNode(t, cap.Argon2idPuzzle{}, 0)
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	np, err := FetchNodePolicy(ctx, client, []string{bootstrapAddr(t, a), bootstrapAddr(t, b)}, 10*time.Second)
	if err != nil {
		t.Fatalf("FetchNodePolicy: %v", err)
	}
	if np.PoW != (PoWInfo{}) {
		t.Fatalf("FetchNodePolicy PoW = %+v, want disabled (zero)", np.PoW)
	}
}

// TestFetchPoWPolicyNoneReachable fails closed: with no bootstrap node answering,
// an adopted policy could only be an offline guess, so the joiner must error.
func TestFetchPoWPolicyNoneReachable(t *testing.T) {
	// A well-formed multiaddr whose peer no host is listening for.
	unreachable := "/ip4/127.0.0.1/tcp/1/p2p/" + paramsNode(t, cap.Argon2idPuzzle{}, 0).ID().String()
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := FetchNodePolicy(ctx, client, []string{unreachable}, 2*time.Second); err == nil {
		t.Fatal("FetchNodePolicy: want error when no bootstrap node is reachable, got nil")
	}
}

// maintNode builds a server host advertising a maintenance policy (repair +
// rebalance) over the params protocol, with PoW disabled. Returns the host to dial.
func maintNode(t *testing.T, repair RepairInfo, rebalance RebalanceInfo) host.Host {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	srv := NewServer(store.NewMemStore(), nil)
	srv.SetMaintenancePolicy(repair, rebalance)
	srv.Register(h)
	return h
}

// TestFetchNodePolicyMaintenanceReconcile confirms the maintenance half of the
// policy reconciles any-enabled + most-aggressive: a joiner facing one node that
// repairs/rebalances rarely and one that does so often adopts the shortest
// interval and smallest rebalance threshold, so it never dilutes the cluster's
// cadence below what an existing node already keeps.
func TestFetchNodePolicyMaintenanceReconcile(t *testing.T) {
	slow := maintNode(t,
		RepairInfo{Enabled: true, Interval: 30 * time.Minute},
		RebalanceInfo{Enabled: true, Interval: time.Hour, Threshold: 0.20})
	fast := maintNode(t,
		RepairInfo{Enabled: true, Interval: 10 * time.Minute},
		RebalanceInfo{Enabled: true, Interval: 15 * time.Minute, Threshold: 0.05})
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	np, err := FetchNodePolicy(ctx, client, []string{bootstrapAddr(t, slow), bootstrapAddr(t, fast)}, 10*time.Second)
	if err != nil {
		t.Fatalf("FetchNodePolicy: %v", err)
	}
	if !np.Repair.Enabled || np.Repair.Interval != 10*time.Minute {
		t.Fatalf("Repair = %+v, want enabled at 10m", np.Repair)
	}
	if !np.Rebalance.Enabled || np.Rebalance.Interval != 15*time.Minute || np.Rebalance.Threshold != 0.05 {
		t.Fatalf("Rebalance = %+v, want enabled at 15m / 0.05", np.Rebalance)
	}
}

// TestFetchNodePolicyMaintenanceAnyEnabled confirms any-enabled semantics: even
// one node running a loop makes the joiner run it, and a zero threshold (a valid
// "no dead-band" policy) is adopted rather than mistaken for "unset".
func TestFetchNodePolicyMaintenanceAnyEnabled(t *testing.T) {
	off := maintNode(t, RepairInfo{}, RebalanceInfo{})
	on := maintNode(t,
		RepairInfo{Enabled: true, Interval: 20 * time.Minute},
		RebalanceInfo{Enabled: true, Interval: 20 * time.Minute, Threshold: 0})
	client := freshHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	np, err := FetchNodePolicy(ctx, client, []string{bootstrapAddr(t, off), bootstrapAddr(t, on)}, 10*time.Second)
	if err != nil {
		t.Fatalf("FetchNodePolicy: %v", err)
	}
	if !np.Repair.Enabled || np.Repair.Interval != 20*time.Minute {
		t.Fatalf("Repair = %+v, want enabled at 20m", np.Repair)
	}
	if !np.Rebalance.Enabled || np.Rebalance.Threshold != 0 {
		t.Fatalf("Rebalance = %+v, want enabled at threshold 0", np.Rebalance)
	}
}
