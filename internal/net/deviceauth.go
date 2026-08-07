package net

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/routing"

	"revika/internal/cap"
	"revika/internal/device"
	"revika/internal/provider"
)

// DeviceAuthNamespace is the DHT key namespace for a User's signed
// device-authorization record (device.Auth), keyed by the same Ed25519 owner
// (master) pubkey as the verify-root: "/revika-devices/<32-byte owner pubkey>".
// It publishes *which devices are currently authorized* so a freshly-enrolled
// device can learn it is in the set and a reader can audit it. Confidentiality is
// not its job — it carries only ML-KEM public keys and an owner signature — so,
// like the verify-root, it is safe in the clear. Validated by deviceAuthValidator.
//
// It complements the sealed companion (FullRootNamespace): the companion is the
// *mechanism* of read revocation (a dropped device gets no seal), while this
// record is the *policy* the owner signs and republishes. A device removed here
// and re-sealed there can no longer open the current root.
const DeviceAuthNamespace = "revika-devices"

// deviceAuthKey is the DHT key a device-auth record for owner is stored under.
func deviceAuthKey(owner cap.SignPubKey) string {
	return "/" + DeviceAuthNamespace + "/" + string(owner[:])
}

// deviceAuthValidator is the record.Validator for the device-auth namespace. It
// enforces the same key-names-the-owner and signature rules as rootValidator, on
// device.Auth, and its Select converges on the newest signed record (highest Seq,
// byte-order tie-break) so replicas agree and a node cannot serve a rolled-back
// device set — an anti-rollback guarantee that matters here because a stale
// record could re-authorize a revoked device.
type deviceAuthValidator struct{}

// Validate implements record.Validator for the device-auth namespace.
func (deviceAuthValidator) Validate(key string, value []byte) error {
	ns, path, err := record.SplitKey(key)
	if err != nil {
		return fmt.Errorf("revika/net: bad device-auth key %q: %w", key, err)
	}
	if ns != DeviceAuthNamespace {
		return fmt.Errorf("revika/net: device-auth validator got namespace %q, want %q", ns, DeviceAuthNamespace)
	}
	if len(path) != cap.SignPubKeySize {
		return fmt.Errorf("revika/net: device-auth key path is %d bytes, want %d", len(path), cap.SignPubKeySize)
	}
	a, err := provider.DecodeDeviceAuth(value)
	if err != nil {
		return fmt.Errorf("revika/net: decode device-auth record: %w", err)
	}
	var owner cap.SignPubKey
	copy(owner[:], path)
	if a.Owner != owner {
		return errors.New("revika/net: device-auth record owner does not match its key")
	}
	if !a.Verify() {
		return errors.New("revika/net: device-auth record failed signature verification")
	}
	return nil
}

// Select implements record.Validator: highest Seq wins, ties broken by a total
// order on the encoded bytes so every replica converges on the same record
// (identical reasoning to rootValidator.Select).
func (deviceAuthValidator) Select(key string, values [][]byte) (int, error) {
	best := -1
	var bestSeq uint64
	for i, v := range values {
		a, err := provider.DecodeDeviceAuth(v)
		if err != nil || !a.Verify() {
			continue
		}
		switch {
		case best == -1 || a.Seq > bestSeq:
			best, bestSeq = i, a.Seq
		case a.Seq == bestSeq && bytes.Compare(v, values[best]) < 0:
			best = i
		}
	}
	if best == -1 {
		return 0, errors.New("revika/net: no valid device-auth record to select")
	}
	return best, nil
}

// PutDeviceAuth publishes the signed device-authorization record a to the DHT
// under its owner's device-auth key. It is a best-effort mirror of the durable
// local devices.json, published on every enroll/revoke so the owner's other
// devices and any reader can resolve the current set. A re-put of an
// equal-or-higher Seq refreshes the record's TTL.
func (d *Discovery) PutDeviceAuth(ctx context.Context, a device.Auth) error {
	val, err := provider.EncodeDeviceAuth(a)
	if err != nil {
		return fmt.Errorf("revika/net: encode device-auth record: %w", err)
	}
	if err := d.dht.PutValue(ctx, deviceAuthKey(a.Owner), val); err != nil {
		return fmt.Errorf("revika/net: publish device-auth for %s: %w", a.Owner, err)
	}
	return nil
}

// GetDeviceAuth resolves the current published device-authorization record for
// owner. ok is false (nil error) when no record exists yet. It re-verifies the
// signature and owner binding defensively even though the validator already gated
// the record on the wire.
func (d *Discovery) GetDeviceAuth(ctx context.Context, owner cap.SignPubKey) (device.Auth, bool, error) {
	val, err := d.dht.GetValue(ctx, deviceAuthKey(owner))
	if err != nil {
		if errors.Is(err, routing.ErrNotFound) {
			return device.Auth{}, false, nil
		}
		return device.Auth{}, false, fmt.Errorf("revika/net: resolve device-auth for %s: %w", owner, err)
	}
	a, err := provider.DecodeDeviceAuth(val)
	if err != nil {
		return device.Auth{}, false, fmt.Errorf("revika/net: decode resolved device-auth: %w", err)
	}
	if a.Owner != owner || !a.Verify() {
		return device.Auth{}, false, errors.New("revika/net: resolved device-auth failed verification")
	}
	return a, true, nil
}
