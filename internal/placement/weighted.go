package placement

import "sync"

// Weighted is a capacity-aware Selector: it hands a node a share of shards
// proportional to its Weight, so a node with twice the weight receives roughly
// twice the shards over time. It uses *smooth* weighted round-robin (the nginx
// SWRR algorithm) rather than randomness, so placement stays deterministic and
// testable, and the interleaving is even (weights 5,1,1 yield a,b,a,c,a,a,a —
// never a,a,a,a,a,b,c) which keeps any short run of shards well spread.
//
// Weight comes from Node.Weight (unset ⇒ 1). To place by advertised capacity,
// derive weights from free bytes with WeightByFree before selecting.
type Weighted struct {
	mu      sync.Mutex
	current map[NodeID]int // SWRR running weights, keyed by node
}

// NewWeighted returns a ready weighted selector.
func NewWeighted() *Weighted { return &Weighted{current: map[NodeID]int{}} }

var _ Selector = (*Weighted)(nil)

// Pick returns the next node by smooth weighted round-robin over the usable
// candidates.
func (w *Weighted) Pick(candidates []Node) (NodeID, error) {
	usable := usableNodes(candidates)
	if len(usable) == 0 {
		return "", ErrNoCandidates
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current == nil {
		w.current = map[NodeID]int{}
	}

	// Drop running weights for nodes that have left the candidate set, so the
	// map never outgrows the live topology.
	present := make(map[NodeID]struct{}, len(usable))
	for _, n := range usable {
		present[n.ID] = struct{}{}
	}
	for id := range w.current {
		if _, ok := present[id]; !ok {
			delete(w.current, id)
		}
	}

	// SWRR: bump every node by its weight, pick the highest running total, then
	// pay for the pick by subtracting the total weight from the winner.
	total := 0
	best := -1
	var winner NodeID
	for _, n := range usable {
		wt := n.weight()
		total += wt
		cur := w.current[n.ID] + wt
		w.current[n.ID] = cur
		if best < 0 || cur > best {
			best = cur
			winner = n.ID
		}
	}
	w.current[winner] -= total
	return winner, nil
}

// WeightByFree returns a copy of candidates with each node's Weight set from its
// advertised Free capacity, in units of unitBytes (a node with unitBytes free
// gets weight 1, with 10*unitBytes free gets weight 10). A node whose Free is
// unknown (0) or below one unit keeps at least weight 1, so it still receives a
// baseline share rather than being starved. unitBytes must be positive; a
// non-positive unit is treated as 1 to avoid a divide-by-zero. Down nodes are
// copied through unchanged (Weighted filters them out).
func WeightByFree(candidates []Node, unitBytes int64) []Node {
	if unitBytes <= 0 {
		unitBytes = 1
	}
	out := make([]Node, len(candidates))
	copy(out, candidates)
	for i := range out {
		out[i].Weight = max(int(out[i].Free/unitBytes), 1)
	}
	return out
}
