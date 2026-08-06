package net

import (
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

// rootRepublishEvery is the default cadence of the background republish loop.
// DHT value records expire after DefaultMaxRecordAge (48h), so the pointer must
// be re-put well before then or a User's namespace vanishes from the network;
// 12h gives three refreshes per lifetime, tolerating transient failures.
const rootRepublishEvery = 12 * time.Hour

// rootKey is the DHT key a root pointer for owner is stored under.
func rootKey(owner cap.SignPubKey) string {
	return "/" + RootNamespace + "/" + string(owner[:])
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
func (rootValidator) Select(key string, values [][]byte) (int, error) {
	best := -1
	var bestSeq uint64
	for i, v := range values {
		rp, err := provider.DecodeRootPointer(v)
		if err != nil || !rp.Verify() {
			continue
		}
		if best == -1 || rp.Seq > bestSeq {
			best, bestSeq = i, rp.Seq
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
