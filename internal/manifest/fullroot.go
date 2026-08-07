package manifest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"revika/internal/cap"
)

// FullRootRecord is the sealed self-root companion published beside the public
// verify-root (RootPointer) so a User's *own* devices — which share the owner
// keys — can recover the decryptable root cap over the network, not just its
// key-stripped verify projection.
//
// Why it exists: per-blob AES keys are random-per-write, and the DHT RootPointer
// is stripped to its verify cap (no AES key). A second device therefore learns
// shard *locations* from the public root but cannot decrypt or three-way-merge
// another device's content. The companion closes that gap by carrying the full
// ReadCap (with its key) sealed to the owner's own ML-KEM-768 public key: every
// device holds the shared owner ML-KEM private key (keys/user.key) and can open
// it, while the public DHT still never sees a decryption key.
//
// Two bindings keep it honest without a second confidential channel:
//
//   - Ed25519 signature over (owner || seq || sealed) proves the owner minted
//     this companion at this seq — an attacker cannot substitute a sealed cap.
//   - The caller binds companion→verify by requiring Open's result to project to
//     the signed verify-root's cap (see net.GetFullRoot): the monotonic, signed
//     Seq lives on the RootPointer, and the companion only *delivers the key* for
//     that already-authenticated cap.
//
// Confidentiality rests on the ML-KEM seal (only owner devices can Unwrap);
// integrity/anti-rollback rest on the paired RootPointer. The Sig here defends
// the sealed bytes in transit so a tampered or stale companion is rejected
// before an expensive Unwrap attempt.
type FullRootRecord struct {
	Owner  cap.SignPubKey
	Seq    uint64
	Sealed []byte // legacy: WrapCap(owner ML-KEM pubkey, full root ReadCap)
	// Seals carries one independent WrapCap of the *same* full root ReadCap per
	// authorized device (Architecture §3.7.2 read-side device revocation): each
	// entry is openable only by a distinct device's ML-KEM key. It coexists with
	// Sealed for backward compatibility — a single-owner-key record built by
	// SealFullRoot sets Sealed and leaves Seals nil; a device-scoped record built
	// by SealFullRootFor sets Seals and leaves Sealed nil. Open tries both. Read
	// revocation is just re-sealing this list to the surviving devices only, so a
	// revoked device's key opens no entry.
	Seals [][]byte
	Sig   []byte // Ed25519 over signingPayload()
}

// signingPayload is the canonical byte string signed and verified for a
// companion record: a domain separator (distinct from RootPointer's tag so the
// two signatures can never be confused), then owner || seq || sealed. The sealed
// ciphertext is committed whole, binding this signature to exactly these bytes.
// The Seals list is appended only when non-empty, and each entry is
// length-prefixed under a count so no two distinct seal lists collide. A legacy
// record (Seals nil, Sealed set) therefore produces byte-for-byte the original
// payload, so its old signature still verifies unchanged.
func (r FullRootRecord) signingPayload() []byte {
	var b bytes.Buffer
	b.WriteString("revika/fullroot/1.0.0\x00")
	b.Write(r.Owner[:])
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], r.Seq)
	b.Write(u[:])
	b.Write(r.Sealed)
	if len(r.Seals) > 0 {
		binary.BigEndian.PutUint64(u[:], uint64(len(r.Seals)))
		b.Write(u[:])
		for _, s := range r.Seals {
			binary.BigEndian.PutUint64(u[:], uint64(len(s)))
			b.Write(u[:])
			b.Write(s)
		}
	}
	return b.Bytes()
}

// SealFullRoot builds and signs a companion record delivering root (a full
// ReadCap, key retained) at sequence seq, sealed to recipient (the owner's own
// ML-KEM-768 public key). signer is the owner Ed25519 key; its public half
// becomes the record's Owner, matching the paired RootPointer.
func SealFullRoot(signer cap.SignKey, recipient cap.PublicKey, root ReadCap, seq uint64) (FullRootRecord, error) {
	sealed, err := WrapCap(recipient, root)
	if err != nil {
		return FullRootRecord{}, fmt.Errorf("manifest: seal full root: %w", err)
	}
	r := FullRootRecord{Owner: signer.Public(), Seq: seq, Sealed: sealed}
	r.Sig = signer.Sign(r.signingPayload())
	return r, nil
}

// SealFullRootFor builds a device-scoped companion delivering root at seq to
// *every* authorized device: one independent WrapCap per recipient ML-KEM key,
// carried in Seals. It is the multi-device generalization of SealFullRoot and the
// mechanism behind read-side device revocation (Architecture §3.7.2) — the caller
// re-seals to the surviving recipients on a revoke, so the dropped device's key
// opens no entry. signer is the owner Ed25519 (master) key; its public half
// becomes Owner, matching the paired RootPointer. recipients must be non-empty.
func SealFullRootFor(signer cap.SignKey, recipients []cap.PublicKey, root ReadCap, seq uint64) (FullRootRecord, error) {
	if len(recipients) == 0 {
		return FullRootRecord{}, errors.New("manifest: seal full root: no recipients")
	}
	seals := make([][]byte, len(recipients))
	for i, rcpt := range recipients {
		s, err := WrapCap(rcpt, root)
		if err != nil {
			return FullRootRecord{}, fmt.Errorf("manifest: seal full root for recipient %d: %w", i, err)
		}
		seals[i] = s
	}
	r := FullRootRecord{Owner: signer.Public(), Seq: seq, Seals: seals}
	r.Sig = signer.Sign(r.signingPayload())
	return r, nil
}

// Verify reports whether r carries a valid signature by its own Owner. It gates
// a companion on the wire (net's fullRootValidator) and defensively on read,
// before any Unwrap is attempted.
func (r FullRootRecord) Verify() bool {
	if len(r.Sig) == 0 || (len(r.Sealed) == 0 && len(r.Seals) == 0) {
		return false
	}
	return r.Owner.Verify(r.signingPayload(), r.Sig)
}

// Open unwraps the sealed full root with the owner's ML-KEM key pair (priv/pub
// from keys/user.key/.pub). It verifies the signature first so a tampered record
// is rejected before decryption. The caller must still bind the result to the
// signed verify-root (companion.VerifyCap() == verifyRoot.Root) — Open only
// recovers the key-bearing cap.
// It opens whichever seal the key fits: the legacy single Sealed blob, or — for
// a device-scoped record — the one entry in Seals wrapped to this device's key.
// Every entry wraps the same cap, so any that opens yields the same root; a key
// belonging to no listed device (e.g. a revoked one) opens none and Open fails.
func (r FullRootRecord) Open(priv cap.PrivateKey, pub cap.PublicKey) (ReadCap, error) {
	if !r.Verify() {
		return ReadCap{}, errors.New("manifest: full-root record failed signature verification")
	}
	if len(r.Sealed) > 0 {
		if c, err := UnwrapCap(priv, pub, r.Sealed); err == nil {
			return c, nil
		}
	}
	for _, s := range r.Seals {
		if c, err := UnwrapCap(priv, pub, s); err == nil {
			return c, nil
		}
	}
	return ReadCap{}, ErrNoSealForKey
}

// ErrNoSealForKey is returned by Open when none of a record's seals fit the
// presented ML-KEM key — the key belongs to no listed (or a revoked) device.
var ErrNoSealForKey = errors.New("manifest: full-root record has no seal for this key")
