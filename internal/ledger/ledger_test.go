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

func TestQuotaEnforced(t *testing.T) {
	// Baseline (no ramp): a new claim past the flat quota is refused and nothing
	// changes.
	l := open(t, Options{QuotaBytes: 150})
	now := time.Unix(1_700_000_000, 0)
	if _, err := l.AddOwner(id(1), alice, 100, now); err != nil {
		t.Fatalf("first claim within quota: %v", err)
	}
	if _, err := l.AddOwner(id(2), alice, 100, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over-quota claim = %v, want ErrQuotaExceeded", err)
	}
	if used, _, _ := l.Account(alice); used != 100 {
		t.Fatalf("alice used after refused claim = %d, want 100 (unchanged)", used)
	}
}

func TestQuotaRampGraduatesNewOwner(t *testing.T) {
	// Axis B: a fresh owner starts weak (10% of a 1000-byte quota) and ramps to the
	// full quota over 100s.
	l := open(t, Options{QuotaBytes: 1000, QuotaRamp: 100 * time.Second, QuotaInitialFraction: 0.1})
	t0 := time.Unix(1_700_000_000, 0)

	// The very first shard is always admitted so the owner can record first_seen —
	// even though its 500 bytes exceed the age-zero effective quota of 100.
	if added, err := l.AddOwner(id(1), alice, 500, t0); err != nil || !added {
		t.Fatalf("first shard: added=%v err=%v, want admitted (first-shard escape)", added, err)
	}
	// A second claim at age zero is held to the ~100-byte effective quota: already
	// at 500 used, it is refused.
	if _, err := l.AddOwner(id(2), alice, 50, t0); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("young owner second claim = %v, want ErrQuotaExceeded", err)
	}

	// Halfway through the ramp (age 50s) the effective quota is 0.1+0.9*0.5 = 0.55 of
	// 1000 = 550. A fresh owner (bob) lands a tiny first shard, then can grow toward
	// 550 but not beyond.
	half := t0.Add(50 * time.Second)
	if added, err := l.AddOwner(id(3), bob, 10, t0); err != nil || !added {
		t.Fatalf("bob first shard: added=%v err=%v", added, err)
	}
	if added, err := l.AddOwner(id(4), bob, 500, half); err != nil || !added {
		t.Fatalf("bob claim within mid-ramp quota (10+500<=550): added=%v err=%v", added, err)
	}
	if _, err := l.AddOwner(id(5), bob, 100, half); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("bob claim over mid-ramp quota (510+100>550) = %v, want ErrQuotaExceeded", err)
	}

	// Past the ramp (age >= 100s) the full 1000-byte quota is available: alice, at
	// 500 used, can add 400 more but not push over 1000.
	after := t0.Add(200 * time.Second)
	if added, err := l.AddOwner(id(6), alice, 400, after); err != nil || !added {
		t.Fatalf("alice claim within full quota (500+400<=1000): added=%v err=%v", added, err)
	}
	if _, err := l.AddOwner(id(7), alice, 200, after); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("alice claim over full quota (900+200>1000) = %v, want ErrQuotaExceeded", err)
	}
}

func TestQuotaRampDisabledIsFlatQuota(t *testing.T) {
	// With QuotaRamp 0 the effective quota is the full QuotaBytes from age zero —
	// the pre-Axis-B behaviour, regardless of QuotaInitialFraction.
	l := open(t, Options{QuotaBytes: 1000, QuotaRamp: 0, QuotaInitialFraction: 0.1})
	now := time.Unix(1_700_000_000, 0)
	if added, err := l.AddOwner(id(1), alice, 600, now); err != nil || !added {
		t.Fatalf("first claim: added=%v err=%v", added, err)
	}
	// Second claim well within the flat 1000 quota (600+300) must be admitted, not
	// throttled as if the owner were young.
	if added, err := l.AddOwner(id(2), alice, 300, now); err != nil || !added {
		t.Fatalf("second claim within flat quota: added=%v err=%v, want admitted", added, err)
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

// TestEntries covers the ledger browser query: unfiltered listing with owner count
// and stripe context, plus the shard-prefix and owner filters and pagination.
func TestEntries(t *testing.T) {
	l := open(t, Options{})
	now := time.Unix(1_700_000_000, 0)

	// id(0xab): claimed by alice+bob, with a stripe. id(0x77): alice only, no stripe.
	striped := id(0xab)
	plain := id(0x77)
	if _, err := l.AddOwner(striped, alice, 100, now); err != nil {
		t.Fatalf("AddOwner striped/alice: %v", err)
	}
	if _, err := l.AddOwner(striped, bob, 100, now); err != nil {
		t.Fatalf("AddOwner striped/bob: %v", err)
	}
	if err := l.PutStripe(striped, 4, 2, []store.ShardID{striped, id(0xcd)}, []byte("grant")); err != nil {
		t.Fatalf("PutStripe: %v", err)
	}
	if _, err := l.AddOwner(plain, alice, 200, now); err != nil {
		t.Fatalf("AddOwner plain/alice: %v", err)
	}

	// Unfiltered: both shards, Total=2, owner counts and stripe context populated.
	res, err := l.Entries(LedgerFilter{})
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if res.Total != 2 || len(res.Entries) != 2 {
		t.Fatalf("unfiltered Total/len = %d/%d, want 2/2", res.Total, len(res.Entries))
	}
	byID := map[store.ShardID]LedgerEntry{}
	for _, e := range res.Entries {
		byID[e.ShardID] = e
	}
	if e := byID[striped]; e.OwnerCount != 2 || !e.HasStripe || e.K != 4 || e.M != 2 || e.Siblings != 2 {
		t.Errorf("striped entry = %+v, want owners=2 stripe k=4 m=2 siblings=2", e)
	}
	if e := byID[plain]; e.OwnerCount != 1 || e.HasStripe || e.Size != 200 {
		t.Errorf("plain entry = %+v, want owners=1 no-stripe size=200", e)
	}

	// Shard-ID hex prefix (case-insensitive) selects only the matching shard.
	res, err = l.Entries(LedgerFilter{ShardHexPrefix: "ab"})
	if err != nil {
		t.Fatalf("Entries prefix: %v", err)
	}
	if res.Total != 1 || len(res.Entries) != 1 || res.Entries[0].ShardID != striped {
		t.Fatalf("prefix filter = %d rows (Total %d), want the striped shard only", len(res.Entries), res.Total)
	}

	// Owner filter: bob claims only the striped shard.
	res, err = l.Entries(LedgerFilter{Owner: bob})
	if err != nil {
		t.Fatalf("Entries owner: %v", err)
	}
	if res.Total != 1 || len(res.Entries) != 1 || res.Entries[0].ShardID != striped {
		t.Fatalf("owner filter = %d rows (Total %d), want bob's one shard", len(res.Entries), res.Total)
	}

	// A LIKE metacharacter in the prefix is escaped, so it matches literally (nothing).
	res, err = l.Entries(LedgerFilter{ShardHexPrefix: "a%"})
	if err != nil {
		t.Fatalf("Entries escaped: %v", err)
	}
	if res.Total != 0 {
		t.Errorf("escaped-wildcard prefix matched %d rows, want 0", res.Total)
	}

	// Pagination: Limit 1 returns one row but reports the full Total; the Offset page
	// returns the other, and the two pages are disjoint.
	p0, err := l.Entries(LedgerFilter{Limit: 1})
	if err != nil {
		t.Fatalf("Entries page0: %v", err)
	}
	p1, err := l.Entries(LedgerFilter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("Entries page1: %v", err)
	}
	if p0.Total != 2 || len(p0.Entries) != 1 || len(p1.Entries) != 1 {
		t.Fatalf("pagination page sizes = %d/%d (Total %d), want 1/1 Total 2", len(p0.Entries), len(p1.Entries), p0.Total)
	}
	if p0.Entries[0].ShardID == p1.Entries[0].ShardID {
		t.Errorf("pagination returned the same shard on both pages: %s", p0.Entries[0].ShardID)
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
