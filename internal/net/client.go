package net

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/store"
	"revika/internal/stripe"
)

// connectTimeout bounds a single dial to a peer.
const connectTimeout = 30 * time.Second

// NetStore is a store.Store whose backend is a remote Node reached over libp2p.
// It is the client half of the shard protocol: from the User side a remote node
// is indistinguishable from a local MemStore/DiskStore, so the pipeline and
// repair layers run over the network unchanged — this is the seam the whole
// architecture is built around.
//
// Each operation opens a fresh stream, exchanges one request/response, and
// closes it. NetStore holds no per-call state and is safe for concurrent use
// (libp2p streams are independent).
type NetStore struct {
	h    host.Host
	peer peer.ID
	// signer, when non-nil, is the User's Ed25519 signing key used to attach an
	// authorization token to PUT/DELETE. Reads (Get/Has/Probe) never sign.
	signer *cap.SignKey
	// grantExpiry is the unix-timestamp expiry stamped into repair grants built
	// by PutStripe. 0 (the default) means the grant never expires — repair must
	// work with no User online.
	grantExpiry int64
}

// NewNetStore returns a store backed by the node identified by peer, dialed
// through h. The peer's addresses must already be known to h (via mDNS, the
// DHT, or an explicit h.Connect / peerstore entry). It signs no requests — use
// it for reads, or against a node that runs no ledger.
func NewNetStore(h host.Host, p peer.ID) *NetStore {
	return &NetStore{h: h, peer: p}
}

// NewNetStoreSigned is NewNetStore plus a signing key: its PUT/DELETE requests
// carry an authorization token proving ownership to a ledger-backed node.
func NewNetStoreSigned(h host.Host, p peer.ID, signer cap.SignKey) *NetStore {
	return &NetStore{h: h, peer: p, signer: &signer}
}

var _ store.Store = (*NetStore)(nil)

// authToken builds the token blob for operation o on id: a signed token when a
// signer is set, otherwise empty (the wire always carries the blob so framing
// is identical whether or not the client signs).
func (n *NetStore) authToken(o op, id store.ShardID) []byte {
	if n.signer == nil {
		return nil
	}
	return buildToken(*n.signer, o, id, n.peer, time.Now().Unix())
}

// openStream dials a fresh stream for one request and applies a deadline.
func (n *NetStore) openStream(ctx context.Context) (network.Stream, error) {
	s, err := n.h.NewStream(ctx, n.peer, ShardProtocol)
	if err != nil {
		return nil, fmt.Errorf("revika/net: open stream to %s: %w", n.peer, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	} else {
		_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	}
	return s, nil
}

// readResp reads a status byte and, for a generic server error, the trailing
// message blob, returning the mapped store error (nil on statusOK).
func readResp(s network.Stream) error {
	st, err := readByte(s)
	if err != nil {
		return fmt.Errorf("revika/net: read status: %w", err)
	}
	if status(st) == statusError {
		msg, err := readBlob(s, MaxShardSize)
		if err != nil {
			return fmt.Errorf("revika/net: read error message: %w", err)
		}
		return statusToErr(statusError, string(msg))
	}
	return statusToErr(status(st), "")
}

func (n *NetStore) Put(ctx context.Context, data []byte) (store.ShardID, error) {
	return n.putRaw(ctx, data, n.authToken(opPut, store.HashOf(data)), nil, nil)
}

// PutStripe stores data and, alongside it, the stripe Descriptor and a freshly
// built repair grant, so the receiving Node records the erasure context and can
// later regenerate the stripe. It authorizes the write with the usual signed
// owner token (a signer is required). This is the write the pipeline uses so
// every shard it stores carries its repair metadata.
func (n *NetStore) PutStripe(ctx context.Context, data []byte, d stripe.Descriptor) (store.ShardID, error) {
	// Without a signer we cannot build a repair grant, so there is no way to
	// authorize the stripe metadata — degrade to a plain, unauthenticated Put.
	// (The receiving node records no stripe row for this shard; a signer-less
	// client is a read/legacy path, not a repair participant.)
	if n.signer == nil {
		return n.Put(ctx, data)
	}
	stripeBytes, err := d.MarshalBinary()
	if err != nil {
		return store.ShardID{}, err
	}
	grant, err := stripe.BuildGrant(*n.signer, d, n.grantExpiry)
	if err != nil {
		return store.ShardID{}, err
	}
	return n.putRaw(ctx, data, n.authToken(opPut, store.HashOf(data)), stripeBytes, grant)
}

// putGrant stores a regenerated shard authorized by a repair grant rather than an
// owner token (the repairing node does not hold the User's signing key). The
// descriptor and grant are replayed exactly as distributed at store time; the
// receiving node verifies the grant names this shard before accepting it under
// the granting User's ownership. Used by RepairStore.
func (n *NetStore) putGrant(ctx context.Context, data []byte, d stripe.Descriptor, grant []byte) (store.ShardID, error) {
	stripeBytes, err := d.MarshalBinary()
	if err != nil {
		return store.ShardID{}, err
	}
	return n.putRaw(ctx, data, nil, stripeBytes, grant)
}

// putRaw sends one PUT with the full 1.1.0 frame: data, then the three trailing
// blobs (token, stripe descriptor, grant), any of which may be empty. It verifies
// the node echoed the shard's true content address.
func (n *NetStore) putRaw(ctx context.Context, data, token, stripeBytes, grant []byte) (store.ShardID, error) {
	s, err := n.openStream(ctx)
	if err != nil {
		return store.ShardID{}, err
	}
	defer s.Close()

	if err := writeByte(s, byte(opPut)); err != nil {
		_ = s.Reset()
		return store.ShardID{}, err
	}
	for _, blob := range [][]byte{data, token, stripeBytes, grant} {
		if err := writeBlob(s, blob); err != nil {
			_ = s.Reset()
			return store.ShardID{}, err
		}
	}
	if err := readResp(s); err != nil {
		return store.ShardID{}, err
	}
	id, err := readID(s)
	if err != nil {
		return store.ShardID{}, fmt.Errorf("revika/net: read id: %w", err)
	}
	// Trust nothing: verify the node addressed the shard by its true hash.
	if want := store.HashOf(data); id != want {
		return store.ShardID{}, fmt.Errorf("revika/net: node returned id %s, want %s", id, want)
	}
	return id, nil
}

func (n *NetStore) Get(ctx context.Context, id store.ShardID) ([]byte, error) {
	s, err := n.openStream(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	if err := writeByte(s, byte(opGet)); err != nil {
		_ = s.Reset()
		return nil, err
	}
	if err := writeID(s, id); err != nil {
		_ = s.Reset()
		return nil, err
	}
	if err := readResp(s); err != nil {
		return nil, err
	}
	data, err := readBlob(s, MaxShardSize)
	if err != nil {
		return nil, fmt.Errorf("revika/net: read shard: %w", err)
	}
	// Self-verify: a content-addressed store must return bytes matching the ID,
	// exactly as DiskStore.Get does. A lying node is caught here.
	if store.HashOf(data) != id {
		return nil, store.ErrCorrupt
	}
	return data, nil
}

func (n *NetStore) Has(ctx context.Context, id store.ShardID) (bool, error) {
	s, err := n.openStream(ctx)
	if err != nil {
		return false, err
	}
	defer s.Close()

	if err := writeByte(s, byte(opHas)); err != nil {
		_ = s.Reset()
		return false, err
	}
	if err := writeID(s, id); err != nil {
		_ = s.Reset()
		return false, err
	}
	if err := readResp(s); err != nil {
		return false, err
	}
	present, err := readByte(s)
	if err != nil {
		return false, fmt.Errorf("revika/net: read presence: %w", err)
	}
	return present != 0, nil
}

func (n *NetStore) Delete(ctx context.Context, id store.ShardID) error {
	s, err := n.openStream(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := writeByte(s, byte(opDelete)); err != nil {
		_ = s.Reset()
		return err
	}
	if err := writeID(s, id); err != nil {
		_ = s.Reset()
		return err
	}
	if err := writeBlob(s, n.authToken(opDelete, id)); err != nil {
		_ = s.Reset()
		return err
	}
	return readResp(s)
}

// Probe issues a proof-of-possession challenge for id and returns true iff the
// node proves it holds the exact bytes. want is the caller's own copy of the
// shard bytes, against which the node's SHA-256(nonce||bytes) response is
// checked in constant time. This lets a verifier confirm a remote shard
// survives without the node shipping the shard back.
//
// nonce must be freshly random per call (NonceSize bytes); reusing a nonce
// would let a node replay an old answer. Callers should source it from a CSPRNG
// (crypto/rand).
func (n *NetStore) Probe(ctx context.Context, id store.ShardID, want, nonce []byte) (bool, error) {
	if len(nonce) != NonceSize {
		return false, fmt.Errorf("revika/net: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	s, err := n.h.NewStream(ctx, n.peer, ProbeProtocol)
	if err != nil {
		return false, fmt.Errorf("revika/net: open probe stream to %s: %w", n.peer, err)
	}
	defer s.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	} else {
		_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	}

	if err := writeID(s, id); err != nil {
		_ = s.Reset()
		return false, err
	}
	if _, err := s.Write(nonce); err != nil {
		_ = s.Reset()
		return false, err
	}
	if err := readResp(s); err != nil {
		return false, err
	}
	got := make([]byte, sha256.Size)
	if _, err := io.ReadFull(s, got); err != nil {
		return false, fmt.Errorf("revika/net: read proof: %w", err)
	}
	h := sha256.New()
	h.Write(nonce)
	h.Write(want)
	expected := h.Sum(nil)
	return subtle.ConstantTimeCompare(got, expected) == 1, nil
}

// Connect ensures h has a live connection to pi, blocking up to connectTimeout.
// A convenience for wiring a NetStore to a node given its AddrInfo.
func Connect(ctx context.Context, h host.Host, pi peer.AddrInfo) error {
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := h.Connect(cctx, pi); err != nil {
		return fmt.Errorf("revika/net: connect %s: %w", pi.ID, err)
	}
	return nil
}
