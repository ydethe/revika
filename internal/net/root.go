package net

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/routing"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/provider"
)

// RootNamespace is the DHT key namespace under which a User's signed RootPointer
// is published, IPNS-style, keyed by their Ed25519 owner pubkey (Architecture
// §4/§6). A record key is "/revika/<32-byte owner pubkey>", so record.SplitKey
// yields ("revika", <owner bytes>). It shares the "/revika" string with the
// Kademlia protocol prefix but is a distinct concept: this names a *value*
// record's namespace, validated by rootValidator; the prefix isolates the wire
// protocol.
const RootNamespace = "revika"

// FullRootNamespace is the DHT key namespace for the sealed self-root companion
// (manifest.FullRootRecord), keyed by the same Ed25519 owner pubkey as the
// verify-root: "/revika-fullcap/<32-byte owner pubkey>". It carries the *full*
// root cap (with its AES key) sealed to the owner's own ML-KEM key so the User's
// other devices can decrypt and merge, while the public verify-root under
// RootNamespace stays key-stripped. Validated by fullRootValidator.
const FullRootNamespace = "revika-fullcap"

// rootRepublishEvery is the default cadence of the background republish loop.
// DHT value records expire after DefaultMaxRecordAge (48h), so the pointer must
// be re-put well before then or a User's namespace vanishes from the network;
// 12h gives three refreshes per lifetime, tolerating transient failures.
const rootRepublishEvery = 12 * time.Hour

// rootKey is the DHT key a root pointer for owner is stored under.
func rootKey(owner cap.SignPubKey) string {
	return "/" + RootNamespace + "/" + string(owner[:])
}

// fullRootKey is the DHT key the sealed self-root companion for owner is stored
// under. It shares the owner-pubkey path with rootKey but a distinct namespace,
// so a reader fetches both records in parallel and binds them (see GetFullRoot).
func fullRootKey(owner cap.SignPubKey) string {
	return "/" + FullRootNamespace + "/" + string(owner[:])
}

// rootValidator is the record.Validator for the revika root-pointer namespace. It
// makes the DHT enforce revika's rules on stored root records: the key must name
// the owner, the value must decode to a RootPointer that key owns, and its
// Ed25519 signature must verify. Select breaks ties by highest Seq, so the DHT
// converges on the newest signed root and a node cannot serve a rolled-back one.
//
// Defence controls (security/Defence.md; primitive P3 in security/frameworks.md):
//
//	SC-8  (Transmission Integrity) — Validate rejects a forged/mismatched/unsigned record;
//	      Select enforces monotonic Seq (anti-rollback) across replicas.
//	D3-MAN (Message Authentication) — the stored value is bound to the owner key by signature.
type rootValidator struct{}

// Validate implements record.Validator: a record is valid only if its key names
// the owner it is signed by and the signature verifies.
func (rootValidator) Validate(key string, value []byte) error {
	ns, path, err := record.SplitKey(key)
	if err != nil {
		return fmt.Errorf("revika/net: bad root key %q: %w", key, err)
	}
	if ns != RootNamespace {
		return fmt.Errorf("revika/net: root validator got namespace %q, want %q", ns, RootNamespace)
	}
	if len(path) != cap.SignPubKeySize {
		return fmt.Errorf("revika/net: root key path is %d bytes, want %d", len(path), cap.SignPubKeySize)
	}
	rp, err := provider.DecodeRootPointer(value)
	if err != nil {
		return fmt.Errorf("revika/net: decode root record: %w", err)
	}
	var owner cap.SignPubKey
	copy(owner[:], path)
	if rp.Owner != owner {
		return errors.New("revika/net: root record owner does not match its key")
	}
	if !rp.Verify() {
		return errors.New("revika/net: root record failed signature verification")
	}
	return nil
}

// Select implements record.Validator: among valid records for a key it picks the
// highest Seq (the newest namespace state). Callers only pass values that already
// passed Validate, but Select re-parses defensively and skips anything unreadable.
//
// Ties on Seq (two devices sharing one owner key that both advanced to the same
// sequence against different roots — a multi-device fork) are broken by a total
// order on the encoded record bytes, NOT by first-seen. First-seen is
// nondeterministic across replicas, so different readers could converge on
// different forks and neither device's next reconcile would see a stable remote
// to merge against. A byte-order tie-break makes every replica and reader agree
// on the same visible tip; the losing device's changes still live in its local
// root file and fold in on its next read-merge-publish (which yields a strictly
// higher Seq containing both sides). A Validator returns one index, so Select
// cannot surface both forks — it only stabilizes which one is seen.
func (rootValidator) Select(key string, values [][]byte) (int, error) {
	best := -1
	var bestSeq uint64
	for i, v := range values {
		rp, err := provider.DecodeRootPointer(v)
		if err != nil || !rp.Verify() {
			continue
		}
		switch {
		case best == -1 || rp.Seq > bestSeq:
			best, bestSeq = i, rp.Seq
		case rp.Seq == bestSeq && bytes.Compare(v, values[best]) < 0:
			best = i
		}
	}
	if best == -1 {
		return 0, errors.New("revika/net: no valid root record to select")
	}
	return best, nil
}

// PutRoot publishes rp to the DHT under its owner's key. The record is stripped
// to its verify projection first — rp.Root loses its AES key — so the public DHT
// never carries a decryption key; the identical signature still verifies because
// RootPointer signs over exactly that projection (see manifest.RootPointer). A
// re-put of an equal-or-higher Seq refreshes the record's TTL.
func (d *Discovery) PutRoot(ctx context.Context, rp manifest.RootPointer) error {
	rp.Root = rp.Root.VerifyCap().ReadCap()
	val, err := provider.EncodeRootPointer(rp)
	if err != nil {
		return fmt.Errorf("revika/net: encode root record: %w", err)
	}
	if err := d.dht.PutValue(ctx, rootKey(rp.Owner), val); err != nil {
		return fmt.Errorf("revika/net: publish root for %s: %w", rp.Owner, err)
	}
	return nil
}

// GetRoot resolves the current published RootPointer for owner from the DHT. ok
// is false (with a nil error) when no record exists yet. The returned pointer
// carries a key-stripped verify cap — enough to locate and integrity-check the
// namespace, but a reader still needs the AES key (held locally or delivered by a
// sealed share) to decrypt. GetRoot re-verifies the signature and owner binding
// defensively even though the validator already gated the record on the wire.
func (d *Discovery) GetRoot(ctx context.Context, owner cap.SignPubKey) (manifest.RootPointer, bool, error) {
	val, err := d.dht.GetValue(ctx, rootKey(owner))
	if err != nil {
		if errors.Is(err, routing.ErrNotFound) {
			return manifest.RootPointer{}, false, nil
		}
		return manifest.RootPointer{}, false, fmt.Errorf("revika/net: resolve root for %s: %w", owner, err)
	}
	rp, err := provider.DecodeRootPointer(val)
	if err != nil {
		return manifest.RootPointer{}, false, fmt.Errorf("revika/net: decode resolved root: %w", err)
	}
	if rp.Owner != owner || !rp.Verify() {
		return manifest.RootPointer{}, false, errors.New("revika/net: resolved root failed verification")
	}
	return rp, true, nil
}

// RepublishRootLoop periodically re-publishes the pointer returned by load, so a
// User's namespace stays resolvable past the DHT record lifetime. It returns
// immediately; the loop runs until ctx is cancelled. load is called on each tick
// (it reads the current local root), so an advanced Seq is picked up
// automatically; a load returning a zero Owner (no namespace yet) is skipped.
func (d *Discovery) RepublishRootLoop(ctx context.Context, load func() manifest.RootPointer, every time.Duration) {
	if every <= 0 {
		every = rootRepublishEvery
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rp := load()
			if (rp.Owner == cap.SignPubKey{}) {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, provideTimeout)
			if err := d.PutRoot(pctx, rp); err != nil {
				d.log.Debug("dht: republish root failed", "event", "root.republish", "owner", rp.Owner, "err", err)
			} else {
				d.log.Debug("dht: republished root", "event", "root.republish", "owner", rp.Owner, "seq", rp.Seq)
			}
			cancel()
		}
	}
}

// fullRootValidator is the record.Validator for the sealed self-root companion
// namespace. It enforces the same key-names-the-owner and signature rules as
// rootValidator, on manifest.FullRootRecord instead of RootPointer, and its
// Select converges on the newest signed companion (highest Seq, byte-order
// tie-break) so replicas agree — mirroring rootValidator exactly.
//
// It never opens the seal: confidentiality is the ML-KEM layer's job, and only
// owner devices hold the key. The validator only proves the record is authentic
// and bound to its key, so a node cannot inject a forged companion.
type fullRootValidator struct{}

// Validate implements record.Validator for the companion namespace.
func (fullRootValidator) Validate(key string, value []byte) error {
	ns, path, err := record.SplitKey(key)
	if err != nil {
		return fmt.Errorf("revika/net: bad full-root key %q: %w", key, err)
	}
	if ns != FullRootNamespace {
		return fmt.Errorf("revika/net: full-root validator got namespace %q, want %q", ns, FullRootNamespace)
	}
	if len(path) != cap.SignPubKeySize {
		return fmt.Errorf("revika/net: full-root key path is %d bytes, want %d", len(path), cap.SignPubKeySize)
	}
	r, err := provider.DecodeFullRoot(value)
	if err != nil {
		return fmt.Errorf("revika/net: decode full-root record: %w", err)
	}
	var owner cap.SignPubKey
	copy(owner[:], path)
	if r.Owner != owner {
		return errors.New("revika/net: full-root record owner does not match its key")
	}
	if !r.Verify() {
		return errors.New("revika/net: full-root record failed signature verification")
	}
	return nil
}

// Select implements record.Validator: highest Seq wins, ties broken by a total
// order on the encoded bytes so every replica converges on the same companion
// (identical reasoning to rootValidator.Select).
func (fullRootValidator) Select(key string, values [][]byte) (int, error) {
	best := -1
	var bestSeq uint64
	for i, v := range values {
		r, err := provider.DecodeFullRoot(v)
		if err != nil || !r.Verify() {
			continue
		}
		switch {
		case best == -1 || r.Seq > bestSeq:
			best, bestSeq = i, r.Seq
		case r.Seq == bestSeq && bytes.Compare(v, values[best]) < 0:
			best = i
		}
	}
	if best == -1 {
		return 0, errors.New("revika/net: no valid full-root record to select")
	}
	return best, nil
}

// PutFullRoot publishes the sealed self-root companion r to the DHT under its
// owner's companion key. Callers publish it alongside PutRoot in the same commit
// so a User's other devices can recover the decryptable root; the public
// verify-root stays key-stripped. Unlike PutRoot it carries a sealed AES key,
// but only the owner's ML-KEM private key can open it.
func (d *Discovery) PutFullRoot(ctx context.Context, r manifest.FullRootRecord) error {
	val, err := provider.EncodeFullRoot(r)
	if err != nil {
		return fmt.Errorf("revika/net: encode full-root record: %w", err)
	}
	if err := d.dht.PutValue(ctx, fullRootKey(r.Owner), val); err != nil {
		return fmt.Errorf("revika/net: publish full-root for %s: %w", r.Owner, err)
	}
	return nil
}

// GetFullRoot resolves the sealed self-root companion for owner and opens it with
// the owner's ML-KEM key pair, returning the decryptable full root cap. ok is
// false (nil error) when no companion exists yet.
//
// It binds the companion to the signed verify-root: the caller passes the
// verify-root's cap (verifyRoot) fetched via GetRoot, and GetFullRoot accepts the
// opened cap only when its verify projection equals verifyRoot. That ties the
// key-bearing cap to the authentic, monotonic Seq the RootPointer signature
// commits to, without the companion needing a second cross-record signature — a
// stale or mismatched companion is rejected rather than merged.
func (d *Discovery) GetFullRoot(ctx context.Context, owner cap.SignPubKey, priv cap.PrivateKey, pub cap.PublicKey, verifyRoot manifest.ReadCap) (manifest.ReadCap, bool, error) {
	val, err := d.dht.GetValue(ctx, fullRootKey(owner))
	if err != nil {
		if errors.Is(err, routing.ErrNotFound) {
			return manifest.ReadCap{}, false, nil
		}
		return manifest.ReadCap{}, false, fmt.Errorf("revika/net: resolve full-root for %s: %w", owner, err)
	}
	r, err := provider.DecodeFullRoot(val)
	if err != nil {
		return manifest.ReadCap{}, false, fmt.Errorf("revika/net: decode resolved full-root: %w", err)
	}
	if r.Owner != owner {
		return manifest.ReadCap{}, false, errors.New("revika/net: resolved full-root owner mismatch")
	}
	full, err := r.Open(priv, pub)
	if err != nil {
		return manifest.ReadCap{}, false, fmt.Errorf("revika/net: open full-root: %w", err)
	}
	// Bind the decryptable cap to the signed verify-root: they must address the
	// identical blob (same locators/params, key aside). A companion that does not
	// match the current verify-root is stale or forged; reject it.
	if !capBytesEqual(full.VerifyCap().ReadCap(), verifyRoot.VerifyCap().ReadCap()) {
		return manifest.ReadCap{}, false, errors.New("revika/net: full-root does not match the signed verify-root")
	}
	return full, true, nil
}

// capBytesEqual reports whether two caps serialize identically — the canonical
// same-blob test used to bind a companion to its verify-root.
func capBytesEqual(a, b manifest.ReadCap) bool {
	ab, err := a.MarshalBinary()
	if err != nil {
		return false
	}
	bb, err := b.MarshalBinary()
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}
