// Package stripe carries the *non-confidential* erasure metadata that lets a
// dumb, untrusted Node take part in repair without ever learning anything about
// the plaintext it stores.
//
// A shard on its own tells a Node nothing about its erasure context: which other
// shards belong to the same Reed–Solomon stripe, or how many are needed to
// reconstruct. A Descriptor supplies exactly that context — K, M, and the ordered
// content addresses of the stripe's shards — and *nothing else*. It deliberately
// omits the per-chunk encryption key (which lives only in the User's manifest), so
// distributing a Descriptor to the nodes that hold a stripe leaks no plaintext:
// the shards are already ciphertext addressed by hash, and repair operates purely
// on ciphertext (erasure.Encode is deterministic, so regenerated shards reproduce
// their exact addresses). This is the "erasure metadata" a repairing node holds.
//
// A Grant is the companion capability. When a node regenerates a missing shard and
// stores it on a fresh node, that node's ledger demands proof of ownership — but
// the repairing node does not hold the User's signing key. A Grant is a User-signed
// token, distributed with the Descriptor, that authorizes storing *any shard whose
// content address is in this stripe*, attributed to the signing User. Content
// addressing bounds it tightly: the bearer can only store the exact bytes that hash
// to one of the listed IDs, so a Grant confers no power to store arbitrary data or
// to grow the stripe beyond its N shards.
package stripe

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"revika/internal/cap"
	"revika/internal/store"
)

// idSize is the byte length of a shard content address.
const idSize = len(store.ShardID{})

// Descriptor is the erasure context of one stripe: its Reed–Solomon parameters
// and the ordered content addresses of its N = K+M shards. Shard index maps
// directly to erasure position (first K are data, the rest parity), so order is
// significant and must be preserved on the wire and in storage.
type Descriptor struct {
	K, M   int
	Shards []store.ShardID
}

// N is the total number of shards in the stripe (K + M).
func (d Descriptor) N() int { return d.K + d.M }

// Contains reports whether id is one of the stripe's shards.
func (d Descriptor) Contains(id store.ShardID) bool {
	return slices.Contains(d.Shards, id)
}

// MarshalBinary serializes the Descriptor in a fixed, canonical layout:
//
//	uint16 K | uint16 M | uint16 N | N * 32-byte shard IDs (position order)
//
// Position order is preserved (never sorted): repair indexes shards by erasure
// position, and the Grant signs over this exact byte string, so any reordering
// would break both reconstruction and signature verification.
func (d Descriptor) MarshalBinary() ([]byte, error) {
	if d.K <= 0 || d.M <= 0 {
		return nil, fmt.Errorf("stripe: invalid params K=%d M=%d", d.K, d.M)
	}
	if d.K > 0xffff || d.M > 0xffff {
		return nil, fmt.Errorf("stripe: params K=%d M=%d exceed uint16", d.K, d.M)
	}
	if len(d.Shards) != d.N() {
		return nil, fmt.Errorf("stripe: have %d shards, want N=%d (K=%d+M=%d)", len(d.Shards), d.N(), d.K, d.M)
	}
	buf := make([]byte, 0, 6+len(d.Shards)*idSize)
	var hdr [6]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(d.K))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(d.M))
	binary.BigEndian.PutUint16(hdr[4:6], uint16(d.N()))
	buf = append(buf, hdr[:]...)
	for _, id := range d.Shards {
		buf = append(buf, id[:]...)
	}
	return buf, nil
}

// UnmarshalDescriptor parses the layout produced by MarshalBinary. It validates
// that the declared N equals K+M and matches the number of shard IDs present, so
// a truncated or malformed blob is rejected rather than silently accepted.
func UnmarshalDescriptor(b []byte) (Descriptor, error) {
	if len(b) < 6 {
		return Descriptor{}, fmt.Errorf("stripe: descriptor too short (%d bytes)", len(b))
	}
	k := int(binary.BigEndian.Uint16(b[0:2]))
	m := int(binary.BigEndian.Uint16(b[2:4]))
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if k <= 0 || m <= 0 {
		return Descriptor{}, fmt.Errorf("stripe: invalid params K=%d M=%d", k, m)
	}
	if n != k+m {
		return Descriptor{}, fmt.Errorf("stripe: declared N=%d != K+M=%d", n, k+m)
	}
	if len(b) != 6+n*idSize {
		return Descriptor{}, fmt.Errorf("stripe: descriptor is %d bytes, want %d for N=%d", len(b), 6+n*idSize, n)
	}
	d := Descriptor{K: k, M: m, Shards: make([]store.ShardID, n)}
	for i := range n {
		off := 6 + i*idSize
		copy(d.Shards[i][:], b[off:off+idSize])
	}
	return d, nil
}

// Grant layout and domain separation.
const (
	// GrantSize is the fixed wire length of a Grant:
	//   owner(32) || expiry(8, big-endian unix seconds) || sig(64)
	GrantSize = cap.SignPubKeySize + 8 + cap.SignatureSize

	// grantDomain is prepended to the signed payload so a Grant signature can
	// never be confused with any other Ed25519 signature the User produces (e.g.
	// an auth token). It is versioned to allow the scheme to evolve.
	grantDomain = "revika/repair-grant/1"
)

// grantPayload is the exact byte string signed and verified for a Grant:
//
//	grantDomain || expiry(8) || MarshalBinary(descriptor)
//
// Signing over the full descriptor binds the Grant to this precise stripe (its
// K, M, and shard set in position order), so it cannot be lifted onto a different
// stripe. Keeping the payload construction in one place guarantees signer and
// verifier hash identical bytes.
func grantPayload(expiry int64, descBytes []byte) []byte {
	buf := make([]byte, 0, len(grantDomain)+8+len(descBytes))
	buf = append(buf, grantDomain...)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(expiry))
	buf = append(buf, e[:]...)
	return append(buf, descBytes...)
}

// BuildGrant signs a repair grant for stripe d under signer. expiry is a unix
// timestamp after which the grant is no longer valid; pass 0 for a grant that
// never expires (the current default — repair must work with no User online, and
// revocation is a planned follow-up).
func BuildGrant(signer cap.SignKey, d Descriptor, expiry int64) ([]byte, error) {
	descBytes, err := d.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pub := signer.Public()
	sig := signer.Sign(grantPayload(expiry, descBytes))

	grant := make([]byte, 0, GrantSize)
	grant = append(grant, pub[:]...)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(expiry))
	grant = append(grant, e[:]...)
	return append(grant, sig...), nil
}

// VerifyGrant checks that grant is a valid repair grant for descriptor d at
// wall-clock now, and returns the owner's public-key bytes (the ledger owner
// identity) on success. It fails if the grant is malformed, signed by a
// different key, does not match d, or has expired (a non-zero expiry in the
// past). now is compared only against a non-zero expiry.
func VerifyGrant(grant []byte, d Descriptor, now time.Time) (owner []byte, err error) {
	if len(grant) != GrantSize {
		return nil, fmt.Errorf("stripe: grant is %d bytes, want %d", len(grant), GrantSize)
	}
	var pub cap.SignPubKey
	copy(pub[:], grant[:cap.SignPubKeySize])
	expiry := int64(binary.BigEndian.Uint64(grant[cap.SignPubKeySize : cap.SignPubKeySize+8]))
	sig := grant[cap.SignPubKeySize+8:]

	if expiry != 0 && now.Unix() > expiry {
		return nil, fmt.Errorf("stripe: grant expired at %d", expiry)
	}
	descBytes, err := d.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !pub.Verify(grantPayload(expiry, descBytes), sig) {
		return nil, fmt.Errorf("stripe: grant signature invalid")
	}
	out := make([]byte, cap.SignPubKeySize)
	copy(out, pub[:])
	return out, nil
}

// Putter is an optional capability a store.Store may implement: store a shard
// together with its stripe Descriptor, so the receiving Node can record the
// erasure context and take part in repair. The pipeline type-asserts for it and
// falls back to a plain Put when a store does not implement it (mock/in-memory
// stores that do not participate in networked repair).
type Putter interface {
	PutStripe(ctx context.Context, data []byte, d Descriptor) (store.ShardID, error)
}
