package placement

import (
	"sync"
	"testing"
)

func nodes(ids ...string) []Node {
	out := make([]Node, len(ids))
	for i, id := range ids {
		out[i] = Node{ID: NodeID(id)}
	}
	return out
}

func TestRoundRobinCyclesDistinct(t *testing.T) {
	rr := NewRoundRobin()
	cand := nodes("a", "b", "c")
	got := make([]NodeID, 6)
	for i := range got {
		id, err := rr.Pick(cand)
		if err != nil {
			t.Fatalf("Pick %d: %v", i, err)
		}
		got[i] = id
	}
	want := []NodeID{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("round-robin order = %v, want %v", got, want)
		}
	}
}

// The first N picks (N = candidate count) must be all-distinct — that is the
// property a stripe's consecutive shard Puts rely on for failure-domain spread.
func TestRoundRobinFirstPassDistinct(t *testing.T) {
	rr := NewRoundRobin()
	cand := nodes("a", "b", "c", "d", "e", "f")
	seen := map[NodeID]bool{}
	for range cand {
		id, err := rr.Pick(cand)
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("node %s repeated within the first pass", id)
		}
		seen[id] = true
	}
}

func TestRoundRobinSkipsDown(t *testing.T) {
	rr := NewRoundRobin()
	cand := []Node{{ID: "a"}, {ID: "b", Down: true}, {ID: "c"}}
	for range 6 {
		id, err := rr.Pick(cand)
		if err != nil {
			t.Fatal(err)
		}
		if id == "b" {
			t.Fatalf("picked a Down node")
		}
	}
}

func TestSelectorsNoCandidates(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    Selector
	}{
		{"roundrobin", NewRoundRobin()},
		{"weighted", NewWeighted()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.s.Pick(nil); err != ErrNoCandidates {
				t.Fatalf("empty: err = %v, want ErrNoCandidates", err)
			}
			allDown := []Node{{ID: "a", Down: true}}
			if _, err := tc.s.Pick(allDown); err != ErrNoCandidates {
				t.Fatalf("all-down: err = %v, want ErrNoCandidates", err)
			}
		})
	}
}

// Pick must not mutate or alias the caller's candidate slice.
func TestUsableDoesNotAliasCaller(t *testing.T) {
	cand := []Node{{ID: "a"}, {ID: "b", Down: true}, {ID: "c"}}
	before := make([]Node, len(cand))
	copy(before, cand)
	NewRoundRobin().Pick(cand)
	for i := range cand {
		if cand[i] != before[i] {
			t.Fatalf("candidate slice mutated at %d: %+v != %+v", i, cand[i], before[i])
		}
	}
}

func TestWeightedProportional(t *testing.T) {
	w := NewWeighted()
	cand := []Node{{ID: "a", Weight: 5}, {ID: "b", Weight: 1}, {ID: "c", Weight: 1}}
	counts := map[NodeID]int{}
	const rounds = 7 * 100 // total weight is 7
	for range rounds {
		id, err := w.Pick(cand)
		if err != nil {
			t.Fatal(err)
		}
		counts[id]++
	}
	// Over full SWRR cycles the split is exactly proportional to the weights.
	if counts["a"] != 500 || counts["b"] != 100 || counts["c"] != 100 {
		t.Fatalf("weighted split = %v, want a:500 b:100 c:100", counts)
	}
}

// SWRR must interleave, not batch: no node should appear in a long unbroken run.
func TestWeightedSmoothInterleave(t *testing.T) {
	w := NewWeighted()
	cand := []Node{{ID: "a", Weight: 5}, {ID: "b", Weight: 1}, {ID: "c", Weight: 1}}
	var seq []NodeID
	for range 7 {
		id, _ := w.Pick(cand)
		seq = append(seq, id)
	}
	// One full cycle of weights 5,1,1: 'a' appears 5 times but is broken up by b/c.
	maxRun, run := 1, 1
	for i := 1; i < len(seq); i++ {
		if seq[i] == seq[i-1] {
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 1
		}
	}
	if maxRun > 2 {
		t.Fatalf("SWRR produced a run of %d (not smooth): %v", maxRun, seq)
	}
}

func TestWeightByFree(t *testing.T) {
	cand := []Node{
		{ID: "big", Free: 100 << 30},
		{ID: "small", Free: 10 << 30},
		{ID: "unknown"}, // Free 0
	}
	got := WeightByFree(cand, 10<<30) // unit = 10 GiB
	byID := map[NodeID]int{}
	for _, n := range got {
		byID[n.ID] = n.Weight
	}
	if byID["big"] != 10 || byID["small"] != 1 || byID["unknown"] != 1 {
		t.Fatalf("weights = %v, want big:10 small:1 unknown:1", byID)
	}
	// The original slice must be untouched.
	if cand[0].Weight != 0 {
		t.Fatalf("WeightByFree mutated the caller's slice")
	}
}

func TestSpreadDistinctDomains(t *testing.T) {
	// Two domains: dc1 has a,b; dc2 has c. A 4-shard stripe must alternate
	// domains, so no domain holds more than it must.
	cand := []Node{
		{ID: "a", Domain: "dc1"},
		{ID: "b", Domain: "dc1"},
		{ID: "c", Domain: "dc2"},
	}
	got, err := Spread(4, cand)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("Spread returned %d assignments, want 4", len(got))
	}
	domainOf := map[NodeID]string{"a": "dc1", "b": "dc1", "c": "dc2"}
	// First two shards land in different domains.
	if domainOf[got[0]] == domainOf[got[1]] {
		t.Fatalf("first two shards share a domain: %v", got)
	}
	// dc2 has one node, so it must be reused; dc1 must use both its nodes before
	// any repeat.
	if got[0] == got[2] && domainOf[got[0]] == "dc1" {
		t.Fatalf("dc1 node reused before its sibling: %v", got)
	}
}

func TestSpreadDistinctNodesWhenEnough(t *testing.T) {
	cand := nodes("a", "b", "c", "d", "e", "f") // each its own domain
	got, err := Spread(6, cand)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[NodeID]bool{}
	for _, id := range got {
		if seen[id] {
			t.Fatalf("Spread reused a node with 6 distinct candidates: %v", got)
		}
		seen[id] = true
	}
}

func TestSpreadOversubscribed(t *testing.T) {
	// More shards than nodes: reuse is unavoidable but must be balanced.
	cand := nodes("a", "b")
	got, err := Spread(5, cand)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[NodeID]int{}
	for _, id := range got {
		counts[id]++
	}
	if counts["a"]+counts["b"] != 5 {
		t.Fatalf("assignments = %v", counts)
	}
	// 5 shards over 2 nodes → 3/2, never 4/1 or 5/0.
	if counts["a"] > 3 || counts["b"] > 3 || counts["a"] == 0 || counts["b"] == 0 {
		t.Fatalf("oversubscription unbalanced: %v", counts)
	}
}

func TestSpreadDeterministic(t *testing.T) {
	cand := []Node{
		{ID: "a", Domain: "dc1", Free: 10},
		{ID: "b", Domain: "dc1", Free: 50},
		{ID: "c", Domain: "dc2", Free: 5},
	}
	first, _ := Spread(6, cand)
	for range 5 {
		got, _ := Spread(6, cand)
		if !equalIDs(first, got) {
			t.Fatalf("Spread not deterministic: %v vs %v", first, got)
		}
	}
	// Within dc1, the roomier node (b, Free 50) is preferred first.
	if first[0] != "b" && first[1] != "b" {
		// b is in dc1; the first dc1 pick should be b before a.
		dc1First := firstOfDomain(first, map[NodeID]string{"a": "dc1", "b": "dc1", "c": "dc2"}, "dc1")
		if dc1First != "b" {
			t.Fatalf("roomier node not preferred within domain: dc1 first = %s", dc1First)
		}
	}
}

func TestSpreadNoCandidates(t *testing.T) {
	if _, err := Spread(3, nil); err != ErrNoCandidates {
		t.Fatalf("err = %v, want ErrNoCandidates", err)
	}
	if got, err := Spread(0, nodes("a")); err != nil || got != nil {
		t.Fatalf("Spread(0) = %v, %v; want nil, nil", got, err)
	}
}

// Selectors must be safe under concurrent Pick (the write path Puts shards
// concurrently). Run with -race.
func TestSelectorConcurrent(t *testing.T) {
	for _, s := range []Selector{NewRoundRobin(), NewWeighted()} {
		cand := nodes("a", "b", "c", "d")
		var wg sync.WaitGroup
		for range 50 {
			wg.Go(func() {
				for range 100 {
					if _, err := s.Pick(cand); err != nil {
						t.Errorf("Pick: %v", err)
						return
					}
				}
			})
		}
		wg.Wait()
	}
}

func equalIDs(a, b []NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func firstOfDomain(ids []NodeID, dom map[NodeID]string, want string) NodeID {
	for _, id := range ids {
		if dom[id] == want {
			return id
		}
	}
	return ""
}

// Guard: usableNodes must preserve caller order (policies depend on it).
func TestUsablePreservesOrder(t *testing.T) {
	cand := []Node{{ID: "c"}, {ID: "a", Down: true}, {ID: "b"}, {ID: "z"}}
	got := usableNodes(cand)
	var ids []string
	for _, n := range got {
		ids = append(ids, string(n.ID))
	}
	want := []string{"c", "b", "z"}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("usableNodes order = %v, want %v", ids, want)
		}
	}
}
