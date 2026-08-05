// Package placement decides *which nodes* a User's shards land on. It is the
// small, pure-Go policy layer the write path consults before dispersing an
// erasure stripe: given a set of candidate nodes and their advertised signals,
// pick targets so no single failure domain can hold enough of a stripe to
// matter (Architecture §5; CLAUDE.md "richer policy planned").
//
// It is deliberately framework-neutral — it knows nothing about libp2p, the
// DHT, or a store.Store. A NodeID is just an opaque string (internal/net maps a
// peer.ID to one via peer.ID.String), and a Node is that ID plus the signals a
// policy weighs: its failure Domain, advertised Free bytes, a relative Weight,
// and whether it is Down. This keeps the policy testable in isolation and lets
// the same decisions run over a mock or a real network unchanged.
//
// Two shapes of decision live here:
//
//   - Selector — a *stateful, per-shard* chooser (Pick returns one node per
//     call). It backs internal/net's PlacementStore, whose pipeline stores a
//     stripe's shards with consecutive Puts: a round-robin Selector then lands
//     them on consecutive distinct nodes, which is the failure-domain diversity
//     the erasure margin depends on. RoundRobin and Weighted implement it.
//   - Spread — a *stripe-level* planner (one call assigns all N shards of a
//     stripe at once). It can guarantee distinct failure domains across the
//     whole stripe, not just distinct consecutive nodes, and is the richer
//     policy a stripe-aware writer adopts once it hands placement the whole
//     stripe instead of one shard at a time.
//
// Defence controls (security/Defence.md; primitive P16 in security/frameworks.md):
//
//	SC-36 (Distributed Processing and Storage) — placement spreads a stripe's K+M shards across
//	      distinct nodes/failure domains so no sub-K subset sits in one failure domain.
package placement

import "errors"

// ErrNoCandidates is returned when a policy is asked to place a shard but no
// usable (non-Down) candidate node is available.
var ErrNoCandidates = errors.New("placement: no candidate nodes available")

// NodeID is the opaque identity of a storage node. internal/net derives it from
// a libp2p peer.ID (peer.ID.String); a policy treats it only as a comparable
// label and never interprets its bytes.
type NodeID string

// Node is a placement candidate: an identity plus the signals a policy weighs.
// The zero Node is *usable* (Down defaults to false) so a caller with no health
// or capacity data can pass bare Node{ID: ...} values and have them all count.
type Node struct {
	// ID is the node's opaque identity.
	ID NodeID
	// Domain is the failure domain the node belongs to — a subnet, rack, or
	// operator — so a policy can spread a stripe across *independent* domains,
	// not merely distinct nodes that might all fail together. Empty means the
	// node is its own domain (its ID).
	Domain string
	// Free is the node's advertised free capacity in bytes. 0 means unknown;
	// capacity-aware policies treat unknown as "no preference".
	Free int64
	// Weight is a relative capacity/preference weight for weighted policies. A
	// value <= 0 is treated as 1, so an unset Weight means "equal share".
	Weight int
	// Down marks a node known to be unavailable; it is excluded from selection.
	Down bool
}

// domain returns the node's effective failure domain (its Domain, or its ID
// when Domain is unset — a node with no declared domain is its own).
func (n Node) domain() string {
	if n.Domain != "" {
		return n.Domain
	}
	return string(n.ID)
}

// weight returns the node's effective weight (>= 1), mapping the unset/invalid
// zero and negative values to 1.
func (n Node) weight() int {
	if n.Weight <= 0 {
		return 1
	}
	return n.Weight
}

// usable reports whether a node may receive shards.
func (n Node) usable() bool { return !n.Down }

// usableNodes returns the subset of candidates that are usable, preserving
// input order (policies rely on a stable candidate order for determinism).
func usableNodes(candidates []Node) []Node {
	out := candidates[:0:0] // fresh backing array, never alias the caller's slice
	for _, n := range candidates {
		if n.usable() {
			out = append(out, n)
		}
	}
	return out
}

// Selector chooses one target node per call, carrying whatever state a policy
// needs to spread successive shards (e.g. a round-robin cursor). Implementations
// must be safe for concurrent use, because the write path Puts shards
// concurrently. The candidate set is passed on every call so a Selector adapts
// to nodes joining or leaving between stripes without being rebuilt.
type Selector interface {
	// Pick returns the next target among the usable candidates, or
	// ErrNoCandidates when none are usable.
	Pick(candidates []Node) (NodeID, error)
}
