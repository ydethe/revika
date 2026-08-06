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
	Sealed []byte // WrapCap(owner ML-KEM pubkey, full root ReadCap)
	Sig    []byte // Ed25519 over signingPayload()
}

// signingPayload is the canonical byte string signed and verified for a
// companion record: a domain separator (distinct from RootPointer's tag so the
// two signatures can never be confused), then owner || seq || sealed. The sealed
// ciphertext is committed whole, binding this signature to exactly these bytes.
func (r FullRootRecord) signingPayload() []byte {
	var b bytes.Buffer
	b.WriteString("revika/fullroot/1.0.0\x00")
	b.Write(r.Owner[:])
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], r.Seq)
	b.Write(u[:])
	b.Write(r.Sealed)
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

// Verify reports whether r carries a valid signature by its own Owner. It gates
// a companion on the wire (net's fullRootValidator) and defensively on read,
// before any Unwrap is attempted.
func (r FullRootRecord) Verify() bool {
	if len(r.Sealed) == 0 || len(r.Sig) == 0 {
		return false
	}
	return r.Owner.Verify(r.signingPayload(), r.Sig)
}

// Open unwraps the sealed full root with the owner's ML-KEM key pair (priv/pub
// from keys/user.key/.pub). It verifies the signature first so a tampered record
// is rejected before decryption. The caller must still bind the result to the
// signed verify-root (companion.VerifyCap() == verifyRoot.Root) — Open only
// recovers the key-bearing cap.
func (r FullRootRecord) Open(priv cap.PrivateKey, pub cap.PublicKey) (ReadCap, error) {
	if !r.Verify() {
		return ReadCap{}, errors.New("manifest: full-root record failed signature verification")
	}
	return UnwrapCap(priv, pub, r.Sealed)
}
