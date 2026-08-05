package placement

import "sort"

// Spread assigns a target node to each of the n shards of one erasure stripe in
// a single call, returning a slice of length n whose i-th element is the node
// for shard i. Where a per-shard Selector only guarantees distinct *consecutive*
// nodes, Spread plans the whole stripe at once and so can guarantee distinct
// *failure domains* across it: it fills domains before nodes and nodes before
// repeats, which is what keeps any k-of-n survivor set reachable when a whole
// domain (subnet/rack/operator) goes down together.
//
// Placement order, by decreasing preference:
//  1. a node in a domain not yet used by this stripe;
//  2. a not-yet-used node in an already-used domain (only once every domain has
//     one shard);
//  3. a repeat of an already-used node (only when n exceeds the usable node
//     count — unavoidable over-subscription, still rotated for evenness).
//
// Within a domain, nodes with more advertised Free capacity are preferred, so
// over-subscription lands on the roomier nodes first. The result is
// deterministic for a given candidate set (ties broken by NodeID), which keeps
// it testable and reproducible. It returns ErrNoCandidates if no node is usable.
//
// This is the "richer policy" a stripe-aware writer adopts once it hands
// placement the whole stripe (its Descriptor's K+M) rather than one shard at a
// time; internal/net's per-shard PlacementStore uses a Selector today.
func Spread(n int, candidates []Node) ([]NodeID, error) {
	if n <= 0 {
		return nil, nil
	}
	usable := usableNodes(candidates)
	if len(usable) == 0 {
		return nil, ErrNoCandidates
	}

	// Order nodes by (domain, -Free, ID) so selection is deterministic and, within
	// a domain, roomier nodes come first.
	sort.Slice(usable, func(i, j int) bool {
		di, dj := usable[i].domain(), usable[j].domain()
		if di != dj {
			return di < dj
		}
		if usable[i].Free != usable[j].Free {
			return usable[i].Free > usable[j].Free
		}
		return usable[i].ID < usable[j].ID
	})

	// Group nodes into per-domain queues, preserving the sorted order, and keep a
	// stable domain order to cycle through.
	queues := map[string][]Node{}
	var domainOrder []string
	for _, node := range usable {
		d := node.domain()
		if _, seen := queues[d]; !seen {
			domainOrder = append(domainOrder, d)
		}
		queues[d] = append(queues[d], node)
	}

	// cursor[d] is the next node to hand out from domain d (round-robin within the
	// domain when it must be reused). used counts assignments per node so we can
	// prefer never-used nodes before repeats.
	cursor := map[string]int{}
	usedCount := map[NodeID]int{}

	out := make([]NodeID, 0, n)
	usedDomains := map[string]struct{}{}
	for len(out) < n {
		// Restart a full pass over domains once every domain has contributed to the
		// current round, so shards keep rotating evenly across domains.
		if len(usedDomains) == len(domainOrder) {
			usedDomains = map[string]struct{}{}
		}
		picked := false
		for _, d := range domainOrder {
			if _, done := usedDomains[d]; done {
				continue
			}
			q := queues[d]
			node := q[cursor[d]%len(q)]
			cursor[d]++
			usedDomains[d] = struct{}{}
			usedCount[node.ID]++
			out = append(out, node.ID)
			picked = true
			if len(out) == n {
				break
			}
		}
		if !picked {
			// Defensive: every domain marked used but round not reset — cannot
			// happen given the reset above, but guard against an infinite loop.
			usedDomains = map[string]struct{}{}
		}
	}
	return out, nil
}
