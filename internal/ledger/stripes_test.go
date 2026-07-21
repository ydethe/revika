package ledger

import (
	"testing"
	"time"

	"revika/internal/store"
)

func siblingSet() []store.ShardID {
	return []store.ShardID{id(10), id(11), id(12), id(13), id(14), id(15)}
}

func TestPutStripeRoundTrip(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	held := id(10)

	// A stripe row requires the shard row to exist (FK) — claim it first.
	if _, err := l.AddOwner(held, alice, 100, now); err != nil {
		t.Fatalf("AddOwner: %v", err)
	}
	sibs := siblingSet()
	grant := []byte("a-signed-repair-grant")
	if err := l.PutStripe(held, 4, 2, sibs, grant); err != nil {
		t.Fatalf("PutStripe: %v", err)
	}

	rows, err := l.Stripes()
	if err != nil {
		t.Fatalf("Stripes: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d stripe rows, want 1", len(rows))
	}
	r := rows[0]
	if r.ShardID != held || r.K != 4 || r.M != 2 {
		t.Fatalf("row = %v k=%d m=%d, want shard=%v 4/2", r.ShardID, r.K, r.M, held)
	}
	if string(r.Grant) != string(grant) {
		t.Fatalf("grant = %q, want %q", r.Grant, grant)
	}
	if len(r.Siblings) != len(sibs) {
		t.Fatalf("siblings len = %d, want %d", len(r.Siblings), len(sibs))
	}
	for i := range sibs {
		if r.Siblings[i] != sibs[i] {
			t.Fatalf("sibling %d = %v, want %v (order not preserved)", i, r.Siblings[i], sibs[i])
		}
	}
}

func TestPutStripeReplace(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	held := id(10)
	l.AddOwner(held, alice, 100, now)

	if err := l.PutStripe(held, 4, 2, siblingSet(), []byte("g1")); err != nil {
		t.Fatal(err)
	}
	if err := l.PutStripe(held, 4, 2, siblingSet(), []byte("g2")); err != nil {
		t.Fatal(err)
	}
	rows, _ := l.Stripes()
	if len(rows) != 1 {
		t.Fatalf("got %d rows after replace, want 1", len(rows))
	}
	if string(rows[0].Grant) != "g2" {
		t.Fatalf("grant = %q, want g2 (not replaced)", rows[0].Grant)
	}
}

func TestPutStripeRequiresGrant(t *testing.T) {
	l := open(t, Options{})
	held := id(10)
	l.AddOwner(held, alice, 100, time.Unix(1_700_000_000, 0))
	if err := l.PutStripe(held, 4, 2, siblingSet(), nil); err == nil {
		t.Fatalf("PutStripe with empty grant: expected error")
	}
}

// TestStripeCascadeOnDrop confirms a stripe row disappears when its shard's last
// owner leaves and the shard record is dropped (FK ON DELETE CASCADE), so the
// repair loop never probes a stripe the node no longer participates in.
func TestStripeCascadeOnDrop(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	held := id(10)
	l.AddOwner(held, alice, 100, now)
	if err := l.PutStripe(held, 4, 2, siblingSet(), []byte("g")); err != nil {
		t.Fatal(err)
	}

	// Alice is the only owner; removing her leaves 0 owners, then DropRecord
	// removes the shard row — the stripe row must cascade away.
	remaining, err := l.RemoveOwner(held, alice)
	if err != nil {
		t.Fatalf("RemoveOwner: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining = %d, want 0", remaining)
	}
	if err := l.DropRecord(held); err != nil {
		t.Fatalf("DropRecord: %v", err)
	}
	rows, err := l.Stripes()
	if err != nil {
		t.Fatalf("Stripes: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d stripe rows after drop, want 0 (cascade failed)", len(rows))
	}
}

func TestStripeCascadeOnCollect(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	held := id(10)
	l.AddOwner(held, alice, 100, now)
	l.PutStripe(held, 4, 2, siblingSet(), []byte("g"))
	l.RemoveOwner(held, alice)

	dropped, err := l.CollectRecord(held, now, false)
	if err != nil || !dropped {
		t.Fatalf("CollectRecord dropped=%v err=%v", dropped, err)
	}
	rows, _ := l.Stripes()
	if len(rows) != 0 {
		t.Fatalf("got %d stripe rows after collect, want 0", len(rows))
	}
}

func TestStripesEmptyByDefault(t *testing.T) {
	l := open(t, Options{})
	rows, err := l.Stripes()
	if err != nil {
		t.Fatalf("Stripes: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(rows))
	}
}
