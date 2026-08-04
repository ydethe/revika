package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"revika/internal/manifest"
)

// RootStore persists (and, in the full system, publishes) the one mutable anchor
// per User: the signed RootPointer mapping the owner identity to the current
// root-directory cap (Architecture §4). It is the seam that isolates the single
// piece of the mount stack not yet networked — DHT/`/revika/root` publication.
// The manifest-backed Provider loads the pointer on construction and Saves a
// freshly signed one after every mutation.
//
// Implementations:
//   - MemRootStore — in-memory, for tests and a single-process mount.
//   - a DHT-backed store publishing the pointer IPNS-style — [planned] (§4, §6);
//     dropping it in here is the only change needed to make the namespace
//     multi-device and network-visible.
type RootStore interface {
	// Load returns the stored pointer. ok is false when none exists yet (a fresh
	// namespace), in which case the Provider bootstraps an empty root.
	Load(ctx context.Context) (rp manifest.RootPointer, ok bool, err error)
	// Save stores rp, replacing any earlier pointer. Callers advance rp.Seq, so a
	// networked implementation can reject a stale (lower-Seq) write (anti-rollback).
	Save(ctx context.Context, rp manifest.RootPointer) error
}

// MemRootStore is an in-memory RootStore for tests and single-process use. Its
// zero value is not ready; use NewMemRootStore.
type MemRootStore struct {
	mu  sync.Mutex
	rp  manifest.RootPointer
	set bool
}

// NewMemRootStore returns an empty in-memory RootStore.
func NewMemRootStore() *MemRootStore { return &MemRootStore{} }

// Load implements RootStore.
func (m *MemRootStore) Load(ctx context.Context) (manifest.RootPointer, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rp, m.set, nil
}

// Save implements RootStore. It rejects a pointer whose Seq does not advance the
// stored one, mirroring the anti-rollback rule a networked store will enforce.
func (m *MemRootStore) Save(ctx context.Context, rp manifest.RootPointer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.set && rp.Seq <= m.rp.Seq {
		return fmt.Errorf("provider: root pointer seq %d does not advance stored seq %d", rp.Seq, m.rp.Seq)
	}
	m.rp = rp
	m.set = true
	return nil
}

// SyncAnchor is the opaque cursor naming a point in the domain's history: the
// root-directory cap at a given sequence. Handed to EnumerateChanges, it lets
// the provider diff that root against the current one (cap equality prunes
// unchanged subtrees). It maps to File Provider's NSFileProviderSyncAnchor and
// to a Cloud Filter USN cursor; a binding layer serializes it with Bytes and
// restores it with ParseAnchor.
type SyncAnchor struct {
	Seq  uint64           `json:"seq"`
	Root manifest.ReadCap `json:"root"`
}

// Bytes serializes the anchor to the opaque byte string a framework stores.
func (a SyncAnchor) Bytes() []byte {
	b, _ := json.Marshal(a) // ReadCap marshals without error; Seq is a uint
	return b
}

// ParseAnchor reverses Bytes.
func ParseAnchor(b []byte) (SyncAnchor, error) {
	var a SyncAnchor
	if err := json.Unmarshal(b, &a); err != nil {
		return SyncAnchor{}, fmt.Errorf("provider: parse sync anchor: %w", err)
	}
	return a, nil
}
