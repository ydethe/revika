package net

// auth.go defines the authorization token that accompanies a PUT or DELETE. It
// is how a Node learns *who* is issuing a write without trusting the (ephemeral)
// libp2p peer identity of the client host.
//
// A token is:
//
//	token = ownerPubKey(32) || timestamp(8, big-endian unix seconds) || sig(64)
//	sig   = Ed25519-Sign( op || shardID(32) || nodePeerID || timestamp )
//
// The signature binds the operation, the exact shard, the *target node*, and a
// timestamp. Binding the node scopes a token to one Node (a token captured by
// node X cannot be replayed to node Y), and the timestamp lets a Node reject
// stale tokens (bounded replay window). Because writes are owner-scoped and
// idempotent, replay within the window is harmless — it only re-asserts or
// re-drops the caller's own claim.

import (
	"encoding/binary"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/store"
)

// authTokenSize is the fixed wire length of a token.
const authTokenSize = cap.SignPubKeySize + 8 + cap.SignatureSize

// tokenSkew bounds how far a token's timestamp may be from the server's clock.
const tokenSkew = 5 * time.Minute

// tokenPayload is the exact byte string signed and verified. Keeping it in one
// place guarantees the client and server hash identical bytes.
func tokenPayload(o op, id store.ShardID, node peer.ID, ts int64) []byte {
	nodeBytes := []byte(node)
	buf := make([]byte, 0, 1+len(id)+len(nodeBytes)+8)
	buf = append(buf, byte(o))
	buf = append(buf, id[:]...)
	buf = append(buf, nodeBytes...)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(ts))
	return append(buf, t[:]...)
}

// buildToken signs an authorization token for operation o on shard id targeting
// node, stamped at ts.
func buildToken(signer cap.SignKey, o op, id store.ShardID, node peer.ID, ts int64) []byte {
	pub := signer.Public()
	sig := signer.Sign(tokenPayload(o, id, node, ts))

	token := make([]byte, 0, authTokenSize)
	token = append(token, pub[:]...)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(ts))
	token = append(token, t[:]...)
	return append(token, sig...)
}

// verifyToken checks a token for operation o on shard id, addressed to this
// node, at wall-clock now. On success it returns the owner's public key bytes
// (the ledger owner identity). Any failure returns ErrUnauthorized.
func verifyToken(token []byte, o op, id store.ShardID, node peer.ID, now time.Time) ([]byte, error) {
	if len(token) != authTokenSize {
		return nil, ErrUnauthorized
	}
	var pub cap.SignPubKey
	copy(pub[:], token[:cap.SignPubKeySize])
	ts := int64(binary.BigEndian.Uint64(token[cap.SignPubKeySize : cap.SignPubKeySize+8]))
	sig := token[cap.SignPubKeySize+8:]

	if d := now.Sub(time.Unix(ts, 0)); d < -tokenSkew || d > tokenSkew {
		return nil, ErrUnauthorized
	}
	if !pub.Verify(tokenPayload(o, id, node, ts), sig) {
		return nil, ErrUnauthorized
	}
	owner := make([]byte, cap.SignPubKeySize)
	copy(owner, pub[:])
	return owner, nil
}
