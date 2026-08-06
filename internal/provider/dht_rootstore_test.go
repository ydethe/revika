package provider

import (
	"context"
	"errors"
	"sync"
	"testing"

	"revika/internal/cap"
	"revika/internal/manifest"
)

// fakePublisher is an in-memory RootPublisher: a single-owner DHT stand-in that
// enforces the same anti-rollback Select the real network validator does.
type fakePublisher struct {
	mu   sync.Mutex
	rp   manifest.RootPointer
	set  bool
	puts int
}

func (f *fakePublisher) PutRoot(_ context.Context, rp manifest.RootPointer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	if f.set && rp.Seq <= f.rp.Seq {
		// The DHT's Select keeps the higher Seq; a stale put is a no-op, not a win.
		return nil
	}
	f.rp, f.set = rp, true
	return nil
}

func (f *fakePublisher) GetRoot(_ context.Context, owner cap.SignPubKey) (manifest.RootPointer, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.set || f.rp.Owner != owner {
		return manifest.RootPointer{}, false, nil
	}
	return f.rp, true, nil
}

// failingStore is a RootStore whose Save always errors, standing in for a mirror
// that is down.
type failingStore struct{ saves int }

func (s *failingStore) Load(context.Context) (manifest.RootPointer, bool, error) {
	return manifest.RootPointer{}, false, nil
}
func (s *failingStore) Save(context.Context, manifest.RootPointer) error {
	s.saves++
	return errors.New("mirror down")
}

func TestDHTRootStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	k, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := &fakePublisher{}
	ds := NewDHTRootStore(pub, owner)

	if _, ok, err := ds.Load(ctx); err != nil || ok {
		t.Fatalf("fresh Load: ok=%v err=%v", ok, err)
	}
	if err := ds.Save(ctx, signRoot(t, k, 1)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := ds.Load(ctx)
	if err != nil || !ok || got.Seq != 1 {
		t.Fatalf("Load: ok=%v seq=%d err=%v", ok, got.Seq, err)
	}
}

func TestDHTRootStoreAntiRollbackAndOwner(t *testing.T) {
	ctx := context.Background()
	k, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ds := NewDHTRootStore(&fakePublisher{}, owner)

	if err := ds.Save(ctx, signRoot(t, k, 5)); err != nil {
		t.Fatalf("Save seq 5: %v", err)
	}
	// The pre-check rejects a non-advancing Seq before it ever hits the network.
	if err := ds.Save(ctx, signRoot(t, k, 5)); err == nil {
		t.Fatal("Save accepted an equal seq")
	}
	if err := ds.Save(ctx, signRoot(t, k, 4)); err == nil {
		t.Fatal("Save accepted a lower seq")
	}
	if err := ds.Save(ctx, signRoot(t, k, 6)); err != nil {
		t.Fatalf("Save seq 6: %v", err)
	}

	// A pointer signed by a different owner is refused: the store is scoped to one
	// identity.
	k2, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ds.Save(ctx, signRoot(t, k2, 7)); err == nil {
		t.Fatal("Save accepted a foreign owner's pointer")
	}
}

func TestMultiRootStore(t *testing.T) {
	ctx := context.Background()
	k, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	primary := NewMemRootStore()
	pub := &fakePublisher{}
	mirror := NewDHTRootStore(pub, owner)
	ms := NewMultiRootStore(nil, primary, mirror)

	if err := ms.Save(ctx, signRoot(t, k, 1)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Load reads the authoritative primary.
	if got, ok, err := ms.Load(ctx); err != nil || !ok || got.Seq != 1 {
		t.Fatalf("Load: ok=%v seq=%d err=%v", ok, got.Seq, err)
	}
	// The mirror got the same pointer.
	if got, ok, _ := pub.GetRoot(ctx, owner); !ok || got.Seq != 1 {
		t.Fatalf("mirror not updated: ok=%v seq=%d", ok, got.Seq)
	}
}

func TestMultiRootStoreMirrorFailureIsSwallowed(t *testing.T) {
	ctx := context.Background()
	k, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	primary := NewMemRootStore()
	down := &failingStore{}
	ms := NewMultiRootStore(nil, primary, down)

	// A mirror outage must not fail the local commit.
	if err := ms.Save(ctx, signRoot(t, k, 1)); err != nil {
		t.Fatalf("Save should succeed despite mirror failure: %v", err)
	}
	if down.saves != 1 {
		t.Fatalf("mirror Save called %d times, want 1", down.saves)
	}
	if got, ok, _ := primary.Load(ctx); !ok || got.Seq != 1 {
		t.Fatalf("primary not committed: ok=%v seq=%d", ok, got.Seq)
	}
}

func TestMultiRootStorePrimaryFailureFails(t *testing.T) {
	ctx := context.Background()
	k, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	// A failing primary must propagate its error and never reach the mirror.
	mirror := &failingStore{}
	ms := NewMultiRootStore(nil, &failingStore{}, mirror)
	if err := ms.Save(ctx, signRoot(t, k, 1)); err == nil {
		t.Fatal("Save should fail when the primary fails")
	}
	if mirror.saves != 0 {
		t.Fatal("mirror should not be written when the primary fails")
	}
}
