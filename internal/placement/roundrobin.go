package placement

import "sync"

// RoundRobin is the default Selector: it hands out usable candidates in turn,
// cycling back to the first after the last. It carries a single cursor, so
// successive Picks — the pipeline's consecutive shard Puts — land on
// consecutive distinct nodes whenever at least that many usable candidates
// exist, giving a stripe the failure-domain spread its erasure margin depends
// on. It weighs no capacity signal; use Weighted for that.
//
// The cursor advances by usable-position, not by absolute index, so a Down node
// in the middle of the candidate set does not create a "gap" that wastes a turn.
type RoundRobin struct {
	mu   sync.Mutex
	next int
}

// NewRoundRobin returns a ready round-robin selector.
func NewRoundRobin() *RoundRobin { return &RoundRobin{} }

var _ Selector = (*RoundRobin)(nil)

// Pick returns the next usable candidate in round-robin order.
func (r *RoundRobin) Pick(candidates []Node) (NodeID, error) {
	usable := usableNodes(candidates)
	if len(usable) == 0 {
		return "", ErrNoCandidates
	}
	r.mu.Lock()
	i := r.next % len(usable)
	r.next++
	r.mu.Unlock()
	return usable[i].ID, nil
}
