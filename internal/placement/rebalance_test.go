package placement

import "testing"

func TestLoadFracAndFree(t *testing.T) {
	cases := []struct {
		name     string
		load     Load
		wantFrac float64
		wantFree int64
	}{
		{"half full", Load{Used: 50, Capacity: 100}, 0.5, 50},
		{"empty", Load{Used: 0, Capacity: 100}, 0, 100},
		{"full", Load{Used: 100, Capacity: 100}, 1, 0},
		{"over full clamps", Load{Used: 150, Capacity: 100}, 1, 0},
		{"unknown capacity", Load{Used: 10, Capacity: 0}, 0, 0},
		{"negative capacity", Load{Used: 10, Capacity: -5}, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.load.Frac(); got != c.wantFrac {
				t.Errorf("Frac() = %v, want %v", got, c.wantFrac)
			}
			if got := c.load.Free(); got != c.wantFree {
				t.Errorf("Free() = %v, want %v", got, c.wantFree)
			}
		})
	}
}

func TestOffloadBytes(t *testing.T) {
	const th = 0.10
	cases := []struct {
		name string
		self Load
		peer Load
		want int64
	}{
		{
			// Gap 0.80 > threshold: move half the gap (0.40) of our capacity = 400.
			name: "big gap sheds half",
			self: Load{Used: 900, Capacity: 1000},
			peer: Load{Used: 100, Capacity: 1000},
			want: 400,
		},
		{
			// Gap exactly at threshold is the dead-band: no move (stops thrashing).
			name: "at threshold stays put",
			self: Load{Used: 60, Capacity: 100},
			peer: Load{Used: 50, Capacity: 100},
			want: 0,
		},
		{
			// Peer is fuller than us: never push uphill.
			name: "peer fuller",
			self: Load{Used: 100, Capacity: 1000},
			peer: Load{Used: 900, Capacity: 1000},
			want: 0,
		},
		{
			// Gap 0.15 > threshold wants half-gap*1000 = 75 bytes, but the small peer
			// has only 15 free: capped by the peer's remaining space.
			name: "capped by peer free space",
			self: Load{Used: 1000, Capacity: 1000},
			peer: Load{Used: 85, Capacity: 100},
			want: 15,
		},
		{
			// A node with no capacity signal reports Frac 0, so it never sheds.
			name: "unknown self capacity",
			self: Load{Used: 500, Capacity: 0},
			peer: Load{Used: 0, Capacity: 1000},
			want: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := OffloadBytes(c.self, c.peer, th); got != c.want {
				t.Errorf("OffloadBytes(%+v, %+v) = %d, want %d", c.self, c.peer, got, c.want)
			}
		})
	}
}

// TestOffloadConverges checks that repeatedly applying the pairwise step to two
// nodes drives their loads together and settles inside the dead-band, without
// overshooting into oscillation.
func TestOffloadConverges(t *testing.T) {
	const th = 0.10
	a := Load{Used: 1000, Capacity: 1000}
	b := Load{Used: 0, Capacity: 1000}
	for range 100 {
		move := OffloadBytes(a, b, th)
		if move == 0 {
			break
		}
		a.Used -= move
		b.Used += move
	}
	gap := a.Frac() - b.Frac()
	if gap < 0 {
		gap = -gap
	}
	if gap > th {
		t.Fatalf("did not converge: final gap %v > threshold %v (a=%v b=%v)", gap, th, a.Frac(), b.Frac())
	}
}
