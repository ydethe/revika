package ledger

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"revika/internal/store"
)

// open returns a ledger backed by a temp-file database.
func open(t *testing.T, opts Options) *Ledger {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "ledger.db"), opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func id(b byte) store.ShardID {
	var s store.ShardID
	for i := range s {
		s[i] = b
	}
	return s
}

var (
	alice = []byte("alice-pubkey-000000000000000000")
	bob   = []byte("bob-pubkey-0000000000000000000000")
)

func TestAddOwnerDedupAndRefcount(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	s1 := id(1)

	// First claim by alice charges her.
	added, err := l.AddOwner(s1, alice, 100, now)
	if err != nil || !added {
		t.Fatalf("AddOwner alice: added=%v err=%v", added, err)
	}
	if used, n, _ := l.Account(alice); used != 100 || n != 1 {
		t.Fatalf("alice account = %d/%d, want 100/1", used, n)
	}

	// Re-PUT by alice is a free renewal, not a second charge.
	added, err = l.AddOwner(s1, alice, 100, now.Add(time.Minute))
	if err != nil || added {
		t.Fatalf("re-put alice: added=%v err=%v, want added=false", added, err)
	}
	if used, n, _ := l.Account(alice); used != 100 || n != 1 {
		t.Fatalf("alice account after re-put = %d/%d, want 100/1", used, n)
	}

	// Bob claims the same (dedup-shared) shard; he is charged the full size too.
	if added, err := l.AddOwner(s1, bob, 100, now); err != nil || !added {
		t.Fatalf("AddOwner bob: added=%v err=%v", added, err)
	}
	if used, _, _ := l.Account(bob); used != 100 {
		t.Fatalf("bob account = %d, want 100", used)
	}
}

func TestStats(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)

	// Empty ledger.
	s, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats empty: %v", err)
	}
	if s.Shards != 0 || s.BytesUsed != 0 || s.Clients != 0 {
		t.Fatalf("empty stats = %+v, want zero", s)
	}

	// Two shards; alice owns both, bob shares the first (dedup).
	s1, s2 := id(1), id(2)
	l.AddOwner(s1, alice, 100, now)
	l.AddOwner(s2, alice, 200, now)
	l.AddOwner(s1, bob, 100, now)

	s, err = l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	// Physical: 2 distinct shards, 300 bytes (each blob counted once).
	if s.Shards != 2 || s.BytesUsed != 300 {
		t.Fatalf("physical stats = %d shards / %d bytes, want 2 / 300", s.Shards, s.BytesUsed)
	}
	if s.Clients != 2 || len(s.Owners) != 2 {
		t.Fatalf("clients = %d (owners %d), want 2", s.Clients, len(s.Owners))
	}
	// Owners ordered by bytes_used desc: alice (300) before bob (100).
	if string(s.Owners[0].Owner) != string(alice) || s.Owners[0].BytesUsed != 300 || s.Owners[0].ShardCount != 2 {
		t.Fatalf("owner[0] = %+v, want alice 300/2", s.Owners[0])
	}
	if string(s.Owners[1].Owner) != string(bob) || s.Owners[1].BytesUsed != 100 || s.Owners[1].ShardCount != 1 {
		t.Fatalf("owner[1] = %+v, want bob 100/1", s.Owners[1])
	}
}

func TestRemoveOwner(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	s1 := id(2)
	l.AddOwner(s1, alice, 50, now)
	l.AddOwner(s1, bob, 50, now)

	// Bob drops his claim; alice's remains.
	remaining, err := l.RemoveOwner(s1, bob)
	if err != nil {
		t.Fatalf("RemoveOwner bob: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining after bob = %d, want 1", remaining)
	}
	if used, _, _ := l.Account(bob); used != 0 {
		t.Fatalf("bob account after remove = %d, want 0", used)
	}

	// Removing a non-owner is unauthorized and changes nothing.
	if _, err := l.RemoveOwner(s1, bob); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("RemoveOwner non-owner = %v, want ErrUnauthorized", err)
	}

	// Alice drops the last claim.
	remaining, err = l.RemoveOwner(s1, alice)
	if err != nil {
		t.Fatalf("RemoveOwner alice: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining after alice = %d, want 0", remaining)
	}
}

func TestQuotaBoundary(t *testing.T) {
	l := open(t, Options{QuotaBytes: 100})
	now := time.Unix(1_700_000_000, 0)

	if _, err := l.AddOwner(id(1), alice, 60, now); err != nil {
		t.Fatalf("first put: %v", err)
	}
	// used+size == quota is allowed (60+40 == 100).
	if _, err := l.AddOwner(id(2), alice, 40, now); err != nil {
		t.Fatalf("boundary put: %v", err)
	}
	// One more byte over the cap is rejected, and nothing is recorded.
	if _, err := l.AddOwner(id(3), alice, 1, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over-quota put = %v, want ErrQuotaExceeded", err)
	}
	if used, n, _ := l.Account(alice); used != 100 || n != 2 {
		t.Fatalf("account after rejected put = %d/%d, want 100/2", used, n)
	}
}

func TestCollectible(t *testing.T) {
	l := open(t, Options{LeaseTTL: time.Hour})
	now := time.Unix(1_700_000_000, 0)

	owned := id(1)
	l.AddOwner(owned, alice, 10, now)

	empty := id(2)
	l.AddOwner(empty, alice, 10, now)
	l.RemoveOwner(empty, alice) // now unowned but the shard row lingers? no — 0 owners

	// Empty-owner shards are always collectible; owned ones are not.
	got, err := l.Collectible(now, false)
	if err != nil {
		t.Fatalf("Collectible: %v", err)
	}
	if !containsOnly(got, empty) {
		t.Fatalf("Collectible(no-expire) = %v, want [%x]", got, empty)
	}

	// With lease expiry on, once alice's lease lapses `owned` becomes collectible.
	got, err = l.Collectible(now.Add(2*time.Hour), true)
	if err != nil {
		t.Fatalf("Collectible expire: %v", err)
	}
	if !containsOnly(got, owned, empty) {
		t.Fatalf("Collectible(expire) = %v, want owned+empty", got)
	}
	// Before expiry, the still-live lease keeps `owned` off the list.
	got, _ = l.Collectible(now, true)
	if !containsOnly(got, empty) {
		t.Fatalf("Collectible(expire, pre-expiry) = %v, want [%x]", got, empty)
	}
}

func TestCollectRecordHonoursReclaim(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	s1 := id(7)
	l.AddOwner(s1, alice, 10, now)
	l.RemoveOwner(s1, alice) // unowned

	// A racing re-claim before collection: CollectRecord must refuse to drop.
	l.AddOwner(s1, bob, 10, now)
	dropped, err := l.CollectRecord(s1, now, false)
	if err != nil {
		t.Fatalf("CollectRecord: %v", err)
	}
	if dropped {
		t.Fatal("CollectRecord dropped a re-claimed shard")
	}

	// Once truly unowned it collects.
	l.RemoveOwner(s1, bob)
	dropped, err = l.CollectRecord(s1, now, false)
	if err != nil || !dropped {
		t.Fatalf("CollectRecord unowned: dropped=%v err=%v", dropped, err)
	}
}

func TestReconcile(t *testing.T) {
	l := open(t, Options{})
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	blobs := store.NewMemStore()

	// gone: a ledger record whose blob was lost — should be dropped, account fixed.
	gone := id(1)
	l.AddOwner(gone, alice, 30, now)

	// kept: a record whose blob is present on disk.
	keptData := []byte("kept shard bytes")
	kept, _ := blobs.Put(ctx, keptData)
	l.AddOwner(kept, alice, int64(len(keptData)), now)

	// orphan: a blob on disk with no ledger record — should be retained + reported.
	blobs.Put(ctx, []byte("orphan shard bytes"))

	rep, err := l.Reconcile(ctx, blobs)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rep.DroppedRecords != 1 {
		t.Fatalf("DroppedRecords = %d, want 1", rep.DroppedRecords)
	}
	if rep.OrphanBlobs != 1 {
		t.Fatalf("OrphanBlobs = %d, want 1", rep.OrphanBlobs)
	}
	// alice was charged for gone (30) + kept (len); after reconcile only kept remains.
	if used, n, _ := l.Account(alice); used != int64(len(keptData)) || n != 1 {
		t.Fatalf("alice account after reconcile = %d/%d, want %d/1", used, n, len(keptData))
	}
}

// TestGCFlow mimics one garbage-collection cycle: list collectible shards,
// atomically drop each still-unowned record, and delete its blob — reclaiming
// the owner's quota.
func TestGCFlow(t *testing.T) {
	l := open(t, Options{})
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	blobs := store.NewMemStore()

	data := []byte("shard to be collected")
	sid, _ := blobs.Put(ctx, data)
	l.AddOwner(sid, alice, int64(len(data)), now)

	// Owned: not collectible.
	if ids, _ := l.Collectible(now, false); len(ids) != 0 {
		t.Fatalf("owned shard collectible: %v", ids)
	}

	// Owner deletes their claim, then GC runs.
	l.RemoveOwner(sid, alice)
	ids, err := l.Collectible(now, false)
	if err != nil || !containsOnly(ids, sid) {
		t.Fatalf("Collectible = %v (err %v), want [%x]", ids, err, sid)
	}
	dropped, err := l.CollectRecord(sid, now, false)
	if err != nil || !dropped {
		t.Fatalf("CollectRecord: dropped=%v err=%v", dropped, err)
	}
	if err := blobs.Delete(ctx, sid); err != nil {
		t.Fatalf("blob delete: %v", err)
	}
	if ok, _ := blobs.Has(ctx, sid); ok {
		t.Fatal("blob survived GC")
	}
	if used, n, _ := l.Account(alice); used != 0 || n != 0 {
		t.Fatalf("alice account after GC = %d/%d, want 0/0", used, n)
	}
}

func containsOnly(got []store.ShardID, want ...store.ShardID) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[store.ShardID]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}
