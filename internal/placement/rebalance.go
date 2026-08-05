package placement

// Load is a node's storage load: bytes Used out of a Capacity budget. It is the
// quantity the diffusion rebalancer equalizes across the network. Balancing the
// *fraction* Used/Capacity (see Frac) rather than raw shard counts is what makes
// heterogeneous nodes converge fairly — a small node and a large node come to
// rest at the same fullness, not the same count (Architecture §3.4).
type Load struct {
	Used     int64 // bytes currently stored
	Capacity int64 // usable budget: min(free disk, operator quota); <=0 means unknown
}

// Frac is the normalized load Used/Capacity, clamped to [0,1]. A node with an
// unknown capacity (<=0) reports 0 so it neither attracts nor sheds shards until
// it can advertise a real budget.
func (l Load) Frac() float64 {
	if l.Capacity <= 0 {
		return 0
	}
	f := float64(l.Used) / float64(l.Capacity)
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// Free is the remaining budget in bytes, never negative.
func (l Load) Free() int64 {
	if f := l.Capacity - l.Used; f > 0 {
		return f
	}
	return 0
}

// OffloadBytes reports how many bytes self should push to peer this round: the
// pairwise dimension-exchange step that, applied repeatedly across a connected
// graph, drives every node's Frac toward the global mean.
//
// It returns 0 unless self is fuller than peer by more than threshold — the
// dead-band (hysteresis) that stops two near-equal nodes from ping-ponging a
// shard back and forth. Above the band it aims to close half the gap so both
// meet in the middle, capped by what peer can actually accept (peer.Free) and by
// what self holds (self.Used). threshold is a fraction in [0,1] (e.g. 0.10).
func OffloadBytes(self, peer Load, threshold float64) int64 {
	if threshold < 0 {
		threshold = 0
	}
	gap := self.Frac() - peer.Frac()
	if gap <= threshold {
		return 0
	}
	// Shed enough (relative to our own capacity) to lower our fraction by half the
	// gap; the peer rises by a comparable amount, so they converge symmetrically.
	want := int64((gap / 2) * float64(self.Capacity))
	if pf := peer.Free(); want > pf {
		want = pf
	}
	if want > self.Used {
		want = self.Used
	}
	if want < 0 {
		want = 0
	}
	return want
}
