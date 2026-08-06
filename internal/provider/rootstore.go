package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"revika/internal/cap"
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
//   - FileRootStore — durable local JSON file (file_rootstore.go), the primary
//     authoritative store.
//   - DHTRootStore — publishes/resolves the pointer IPNS-style over the DHT (§4,
//     §6), making the namespace multi-device and network-visible.
//   - MultiRootStore — composes a durable primary with best-effort mirrors (e.g.
//     FileRootStore primary + DHTRootStore mirror), the combination revika-ctl
//     uses so a DHT publish failure never fails a local commit.
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

// RootPublisher is the DHT seam a DHTRootStore rides on, kept as a local
// interface so this package never imports internal/net (which imports this one —
// the interface breaks the cycle). *net.Discovery satisfies it structurally via
// PutRoot/GetRoot. PutRoot strips the cap to its verify projection before
// publishing, so a mirror never leaks a decryption key to the public DHT.
type RootPublisher interface {
	PutRoot(ctx context.Context, rp manifest.RootPointer) error
	GetRoot(ctx context.Context, owner cap.SignPubKey) (rp manifest.RootPointer, ok bool, err error)
}

// DHTRootStore is a RootStore that publishes and resolves the signed RootPointer
// over the DHT (Architecture §4/§6). It is scoped to one owner so Load resolves
// exactly that identity's namespace and Save refuses to publish a pointer signed
// by anyone else. Used directly it makes a namespace network-visible; used as a
// MultiRootStore mirror it keeps the DHT in step with the durable local file.
//
// A DHT record is public and carries only a *verify* cap (no AES key): Load
// yields shard locations and integrity, but decrypting still needs the read key
// (held locally or delivered by a sealed share).
type DHTRootStore struct {
	pub   RootPublisher
	owner cap.SignPubKey
}

// NewDHTRootStore returns a DHTRootStore publishing/resolving owner's pointer via
// pub.
func NewDHTRootStore(pub RootPublisher, owner cap.SignPubKey) *DHTRootStore {
	return &DHTRootStore{pub: pub, owner: owner}
}

// Load implements RootStore by resolving the owner's current pointer from the
// DHT. ok is false when none is published yet.
func (d *DHTRootStore) Load(ctx context.Context) (manifest.RootPointer, bool, error) {
	return d.pub.GetRoot(ctx, d.owner)
}

// Save implements RootStore by publishing rp to the DHT. It pre-checks the same
// invariants the on-wire validator enforces — valid signature, owner match, and a
// Seq that advances any record already published — so a stale or foreign pointer
// is rejected before it hits the network.
func (d *DHTRootStore) Save(ctx context.Context, rp manifest.RootPointer) error {
	if !rp.Verify() {
		return fmt.Errorf("provider: refusing to publish an unsigned or invalid root pointer")
	}
	if rp.Owner != d.owner {
		return fmt.Errorf("provider: root pointer owner mismatch (store is scoped to a different identity)")
	}
	if cur, ok, err := d.pub.GetRoot(ctx, d.owner); err != nil {
		// A resolution failure must not block a first publish; treat it as "unknown"
		// and let the on-wire validator's Select enforce monotonicity across replicas.
		_ = err
	} else if ok && rp.Seq <= cur.Seq {
		return fmt.Errorf("provider: root pointer seq %d does not advance published seq %d", rp.Seq, cur.Seq)
	}
	return d.pub.PutRoot(ctx, rp)
}

// MultiRootStore composes one durable, authoritative primary RootStore with any
// number of best-effort mirrors. Load reads only the primary (the source of
// truth); Save writes the primary first and, only if that succeeds, fans out to
// the mirrors — a mirror failure is logged, not propagated, so publishing to the
// DHT can never fail a local commit. This is the revika-ctl combination:
// FileRootStore primary + DHTRootStore mirror.
type MultiRootStore struct {
	primary RootStore
	mirrors []RootStore
	log     *slog.Logger
}

// NewMultiRootStore returns a MultiRootStore over primary and mirrors. A nil log
// discards mirror-failure diagnostics.
func NewMultiRootStore(log *slog.Logger, primary RootStore, mirrors ...RootStore) *MultiRootStore {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &MultiRootStore{primary: primary, mirrors: mirrors, log: log}
}

// Load implements RootStore, reading from the authoritative primary only.
func (m *MultiRootStore) Load(ctx context.Context) (manifest.RootPointer, bool, error) {
	return m.primary.Load(ctx)
}

// Save implements RootStore: the primary commit must succeed (its error is
// returned); each mirror is then written best-effort, its failure logged and
// swallowed so a mirror outage never rolls back a durable local commit.
func (m *MultiRootStore) Save(ctx context.Context, rp manifest.RootPointer) error {
	if err := m.primary.Save(ctx, rp); err != nil {
		return err
	}
	for _, mir := range m.mirrors {
		if err := mir.Save(ctx, rp); err != nil {
			m.log.Warn("provider: mirror root publish failed", "event", "root.mirror", "owner", rp.Owner, "seq", rp.Seq, "err", err)
		}
	}
	return nil
}
