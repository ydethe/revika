package net

import (
	"sync"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// recorder is a peerBlocker that records every Block call, for asserting on the
// abuse detector's decisions without a live host.
type recorder struct {
	mu      sync.Mutex
	blocked []peer.ID
	reasons []string
}

func (r *recorder) Block(p peer.ID, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocked = append(r.blocked, p)
	r.reasons = append(r.reasons, reason)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.blocked)
}

// testPeerID mints a genuine libp2p peer ID for tests.
func testPeerID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func TestAbuseRebalanceBaselineNoBan(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{RebalanceInterval: time.Hour, Tolerance: 10 * time.Minute}, nil)
	p := testPeerID(t)
	base := time.Now()

	// The very first sweep only establishes the baseline; it is never a violation.
	m.RecordRebalanceMove(p, base)
	if rec.count() != 0 {
		t.Fatalf("first move banned the peer; baseline should be judgement-free")
	}
}

func TestAbuseRebalanceOnScheduleNoBan(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{RebalanceInterval: time.Hour, Tolerance: 10 * time.Minute, Coalesce: time.Minute}, nil)
	p := testPeerID(t)
	base := time.Now()

	m.RecordRebalanceMove(p, base)                    // baseline sweep
	m.RecordRebalanceMove(p, base.Add(time.Hour))     // exactly one interval later
	m.RecordRebalanceMove(p, base.Add(2*time.Hour+1)) // a further interval later
	if rec.count() != 0 {
		t.Fatalf("on-schedule peer was banned: %d blocks", rec.count())
	}
}

func TestAbuseRebalanceSlowNoBan(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{RebalanceInterval: time.Hour, Tolerance: 10 * time.Minute, Coalesce: time.Minute}, nil)
	p := testPeerID(t)
	base := time.Now()

	m.RecordRebalanceMove(p, base)                  // baseline sweep
	m.RecordRebalanceMove(p, base.Add(3*time.Hour)) // far too slow — perfectly fine
	if rec.count() != 0 {
		t.Fatalf("a slow rebalancer was banned; only too-fast is abuse")
	}
}

func TestAbuseRebalanceFastBan(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{RebalanceInterval: time.Hour, Tolerance: 10 * time.Minute, Coalesce: time.Minute}, nil)
	p := testPeerID(t)
	base := time.Now()

	m.RecordRebalanceMove(p, base) // baseline sweep
	// Next sweep after only 20m: gap (20m) < interval-tolerance (50m) → too fast.
	m.RecordRebalanceMove(p, base.Add(20*time.Minute))
	if rec.count() != 1 {
		t.Fatalf("too-fast rebalancer not banned: %d blocks", rec.count())
	}
	if rec.reasons[0] == "" {
		t.Fatalf("ban reason empty")
	}
}

func TestAbuseRebalanceCoalesceNoBan(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{RebalanceInterval: time.Hour, Tolerance: 10 * time.Minute, Coalesce: 5 * time.Minute}, nil)
	p := testPeerID(t)
	base := time.Now()

	// A single sweep sends many back-to-back PUTs; each is within the coalesce
	// window of the previous, so they fold into one event and never trip the check.
	m.RecordRebalanceMove(p, base)
	for i := 1; i <= 20; i++ {
		m.RecordRebalanceMove(p, base.Add(time.Duration(i)*30*time.Second))
	}
	if rec.count() != 0 {
		t.Fatalf("coalesced burst banned as off-schedule: %d blocks", rec.count())
	}
}

func TestAbuseRebalanceDisabledInterval(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{RebalanceInterval: 0}, nil)
	p := testPeerID(t)
	base := time.Now()

	// No schedule to measure against: off-schedule policing is inert.
	m.RecordRebalanceMove(p, base)
	m.RecordRebalanceMove(p, base.Add(time.Second))
	m.RecordRebalanceMove(p, base.Add(2*time.Second))
	if rec.count() != 0 {
		t.Fatalf("off-schedule policing fired with no schedule: %d blocks", rec.count())
	}
}

func TestAbusePossessionStrikes(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{Strikes: 3, Decay: 24 * time.Hour}, nil)
	p := testPeerID(t)
	base := time.Now()

	m.RecordPossessionLie(p, base)
	m.RecordPossessionLie(p, base.Add(time.Minute))
	if rec.count() != 0 {
		t.Fatalf("banned before reaching the strike budget: %d blocks", rec.count())
	}
	m.RecordPossessionLie(p, base.Add(2*time.Minute)) // third strike → ban
	if rec.count() != 1 {
		t.Fatalf("not banned at the strike budget: %d blocks", rec.count())
	}
}

func TestAbusePossessionStrikesDecay(t *testing.T) {
	rec := &recorder{}
	m := NewAbuseMonitor(rec, AbuseConfig{Strikes: 3, Decay: time.Hour}, nil)
	p := testPeerID(t)
	base := time.Now()

	// Two strikes, then a long gap that ages them out beyond the decay window, then
	// two fresh strikes: only two live strikes remain, below the budget.
	m.RecordPossessionLie(p, base)
	m.RecordPossessionLie(p, base.Add(time.Minute))
	m.RecordPossessionLie(p, base.Add(2*time.Hour)) // old two now expired
	m.RecordPossessionLie(p, base.Add(2*time.Hour+time.Minute))
	if rec.count() != 0 {
		t.Fatalf("expired strikes still counted toward a ban: %d blocks", rec.count())
	}
}

func TestAbuseConfigDefaults(t *testing.T) {
	c := AbuseConfig{RebalanceInterval: time.Hour}.withDefaults()
	if c.Tolerance != defaultAbuseTolerance {
		t.Errorf("Tolerance = %v, want %v", c.Tolerance, defaultAbuseTolerance)
	}
	if c.Strikes != defaultAbuseStrikes {
		t.Errorf("Strikes = %d, want %d", c.Strikes, defaultAbuseStrikes)
	}
	if c.Decay != defaultAbuseDecay {
		t.Errorf("Decay = %v, want %v", c.Decay, defaultAbuseDecay)
	}
	// Coalesce = min(interval/4, 5m); with a 1h interval that is 15m capped to 5m.
	if c.Coalesce != defaultAbuseCoalesceCap {
		t.Errorf("Coalesce = %v, want %v (cap)", c.Coalesce, defaultAbuseCoalesceCap)
	}
	// A short interval makes interval/4 the binding constraint.
	c2 := AbuseConfig{RebalanceInterval: 8 * time.Minute}.withDefaults()
	if c2.Coalesce != 2*time.Minute {
		t.Errorf("Coalesce = %v, want 2m (interval/4)", c2.Coalesce)
	}
}
