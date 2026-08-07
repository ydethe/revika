// Package device models a User's *devices* as revocable members of the one User
// principal (Architecture §3.7.2). Today every device of a User shares the owner
// keys and is therefore unrevocable; this package makes an individual device a
// first-class, individually-keyed member so a lost or compromised one can be
// retired without rotating the whole owner identity.
//
// The trust model: the User is a principal, not a single keyholder. It is
// realized by
//
//   - a *master credential* — the owner Ed25519 signing key, the sole authority
//     that signs the device set. It is kept offline and appears only to enroll or
//     revoke a device; and
//   - one or more *devices*, each with its own ML-KEM-768 keypair (the same key
//     type cap uses to receive shares), authorized to read on the User's behalf.
//
// The authorization is a signed **device-authorization record** (Auth): the
// owner-signed, monotonic list of the ML-KEM public keys currently allowed to
// open the User's sealed self-root companion (manifest.FullRootRecord). Read
// revocation rides on that: the companion is sealed once per authorized device,
// so dropping a device from the record and re-sealing to the survivors means the
// revoked device's key no longer opens the current root. As with every revika
// revocation this is forward-only — a revoked device keeps whatever plaintext it
// already downloaded; the record only governs future bytes.
//
// This package is pure and offline: it never touches the network. The CLI
// (revika-ctl device) drives it, persists the record beside root.json, and
// mirrors it to the DHT best-effort.
package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"revika/internal/cap"
)

// IDSize is the length of a device ID: a SHA-256 digest of the device's ML-KEM
// public key. The public key itself is 1184 bytes, unwieldy as a handle, so a
// device is named on the CLI and in the record by this stable 32-byte hash.
const IDSize = sha256.Size

// ID is the stable handle for a device: SHA-256 of its ML-KEM public key. It is
// derived, not chosen, so two records built from the same key agree on it and a
// device cannot spoof another's ID without its key.
type ID [IDSize]byte

// NewID derives a device ID from its ML-KEM public key.
func NewID(pub cap.PublicKey) ID {
	return ID(sha256.Sum256(pub[:]))
}

// String renders an ID as lowercase hex — its CLI and display form.
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Short renders the first 8 bytes of an ID as hex, a git-style abbreviation for
// human-facing listings. Full IDs remain the canonical handle.
func (id ID) Short() string { return hex.EncodeToString(id[:8]) }

// Member is one authorized device: its derived ID, its ML-KEM public key (the
// seal recipient), and an optional human label. Added is the record Seq at which
// the device was enrolled, purely informational.
type Member struct {
	ID    ID
	Pub   cap.PublicKey
	Label string
	Added uint64
}

// Auth is a device-authorization record (DAR): the owner-signed, monotonic set
// of devices allowed to open the User's sealed self-root companion. It is the
// authority read revocation consults — a device absent from the current record
// gets no companion seal and so cannot decrypt the current root.
//
// Seq is monotonic like the RootPointer's: enroll and revoke both mint a strictly
// higher Seq, so a stale record (e.g. one a revoked device cached) can never win
// over the current one. Members is kept sorted by ID so the signed payload is
// canonical regardless of insertion order.
type Auth struct {
	Owner   cap.SignPubKey
	Seq     uint64
	Members []Member
	Sig     []byte // Ed25519 over signingPayload(), by the master (owner) key
}

// signingPayload is the canonical byte string signed and verified for a record: a
// domain separator (distinct from every other revika signature so the two can
// never be confused), then owner || seq || sorted members. Each field is
// length-prefixed so no two distinct records can share an encoding.
func (a Auth) signingPayload() []byte {
	members := append([]Member(nil), a.Members...)
	sort.Slice(members, func(i, j int) bool {
		return bytes.Compare(members[i].ID[:], members[j].ID[:]) < 0
	})
	var b bytes.Buffer
	b.WriteString("revika/deviceauth/1.0.0\x00")
	b.Write(a.Owner[:])
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], a.Seq)
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], uint64(len(members)))
	b.Write(u[:])
	for _, m := range members {
		b.Write(m.ID[:])
		b.Write(m.Pub[:])
		binary.BigEndian.PutUint64(u[:], uint64(len(m.Label)))
		b.Write(u[:])
		b.WriteString(m.Label)
		binary.BigEndian.PutUint64(u[:], m.Added)
		b.Write(u[:])
	}
	return b.Bytes()
}

// Sign fills in Owner and Sig, returning a signed copy of a. signer is the master
// (owner) Ed25519 key; only it can advance the device set.
func (a Auth) Sign(signer cap.SignKey) Auth {
	a.Owner = signer.Public()
	a.Sig = signer.Sign(a.signingPayload())
	return a
}

// Verify reports whether a carries a valid signature by its own Owner. It also
// rejects a record whose Member.ID does not derive from its Pub, so a listed
// device cannot claim an ID it has no key for.
func (a Auth) Verify() bool {
	if len(a.Sig) == 0 {
		return false
	}
	for _, m := range a.Members {
		if m.ID != NewID(m.Pub) {
			return false
		}
	}
	return a.Owner.Verify(a.signingPayload(), a.Sig)
}

// Authorized reports whether id is a member of the current record.
func (a Auth) Authorized(id ID) bool {
	for _, m := range a.Members {
		if m.ID == id {
			return true
		}
	}
	return false
}

// PubOf returns the ML-KEM public key of member id, and whether it was found.
func (a Auth) PubOf(id ID) (cap.PublicKey, bool) {
	for _, m := range a.Members {
		if m.ID == id {
			return m.Pub, true
		}
	}
	return cap.PublicKey{}, false
}

// Recipients returns the ML-KEM public keys of every authorized device — the
// seal-recipient set for the self-root companion.
func (a Auth) Recipients() []cap.PublicKey {
	out := make([]cap.PublicKey, len(a.Members))
	for i, m := range a.Members {
		out[i] = m.Pub
	}
	return out
}

// With returns an unsigned copy of a that adds device pub with the given label,
// at a Seq one higher than a's. Re-adding an already-authorized device is an
// error (the caller should revoke first if re-keying). The result must be Signed
// before use.
func (a Auth) With(pub cap.PublicKey, label string) (Auth, error) {
	id := NewID(pub)
	if a.Authorized(id) {
		return Auth{}, fmt.Errorf("device: %s is already authorized", id.Short())
	}
	next := a.clone()
	next.Seq = a.Seq + 1
	next.Sig = nil
	next.Members = append(next.Members, Member{ID: id, Pub: pub, Label: label, Added: next.Seq})
	sortMembers(next.Members)
	return next, nil
}

// Without returns an unsigned copy of a that removes device id, at a Seq one
// higher than a's. Removing an absent device is an error so a typo does not
// silently mint a no-op revocation. The result must be Signed before use.
func (a Auth) Without(id ID) (Auth, error) {
	if !a.Authorized(id) {
		return Auth{}, fmt.Errorf("device: %s is not authorized", id.Short())
	}
	next := a.clone()
	next.Seq = a.Seq + 1
	next.Sig = nil
	next.Members = next.Members[:0]
	for _, m := range a.Members {
		if m.ID != id {
			next.Members = append(next.Members, m)
		}
	}
	return next, nil
}

// Resolve maps a full-or-prefix hex handle to the unique member it names, the
// way git resolves an abbreviated hash. An empty, unknown, or ambiguous handle is
// an error.
func (a Auth) Resolve(handle string) (Member, error) {
	handle = normalizeHandle(handle)
	if handle == "" {
		return Member{}, errors.New("device: empty device id")
	}
	var match *Member
	for i := range a.Members {
		if bytes.HasPrefix([]byte(a.Members[i].ID.String()), []byte(handle)) {
			if match != nil {
				return Member{}, fmt.Errorf("device: id %q is ambiguous; give more characters", handle)
			}
			match = &a.Members[i]
		}
	}
	if match == nil {
		return Member{}, fmt.Errorf("device: no authorized device matches id %q", handle)
	}
	return *match, nil
}

func (a Auth) clone() Auth {
	out := a
	out.Members = append([]Member(nil), a.Members...)
	return out
}

func sortMembers(ms []Member) {
	sort.Slice(ms, func(i, j int) bool { return bytes.Compare(ms[i].ID[:], ms[j].ID[:]) < 0 })
}

func normalizeHandle(h string) string {
	// Lowercase hex only; tolerate surrounding whitespace.
	out := make([]byte, 0, len(h))
	for _, c := range []byte(h) {
		switch {
		case c >= 'A' && c <= 'F':
			out = append(out, c+('a'-'A'))
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
			out = append(out, c)
		}
	}
	return string(out)
}
