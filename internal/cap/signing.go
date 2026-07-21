package cap

// signing.go adds a User *signing* identity, distinct from the X25519 recipient
// identity above. Where the X25519 keys deliver read-capabilities (confidentiality
// only, no sender identity), the signing key proves *who* a request comes from.
//
// It is an Ed25519 keypair. A User signs short authorization tokens with it (see
// internal/net), and a Node verifies those tokens to decide who owns a shard —
// so only the holder of the signing key can delete or renew what they stored.
// The public key is the User's stable owner identity, independent of the
// (ephemeral) libp2p peer identity of whatever host they happen to dial from.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Signing key sizes, re-exported from crypto/ed25519 for callers that build
// fixed-width wire frames.
const (
	SignPubKeySize = ed25519.PublicKeySize  // 32
	SignKeySize    = ed25519.PrivateKeySize // 64
	SignatureSize  = ed25519.SignatureSize  // 64
)

// SignKey is a User's Ed25519 private signing key. Whoever holds it can assert
// ownership of shards; keep it secret. It is the full 64-byte expanded private
// key (seed||public), matching crypto/ed25519.
type SignKey [SignKeySize]byte

// SignPubKey is a User's Ed25519 public key: their stable owner identity, safe
// to publish. A Node records it as the owner of the shards a User stores.
type SignPubKey [SignPubKeySize]byte

// GenerateSigningKey returns a fresh Ed25519 signing keypair from the OS CSPRNG.
func GenerateSigningKey() (SignKey, SignPubKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SignKey{}, SignPubKey{}, fmt.Errorf("cap: generate signing key: %w", err)
	}
	var k SignKey
	var p SignPubKey
	copy(k[:], priv)
	copy(p[:], pub)
	return k, p, nil
}

// Sign returns the Ed25519 signature of msg under k.
func (k SignKey) Sign(msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(k[:]), msg)
}

// Public derives the public key matching k.
func (k SignKey) Public() SignPubKey {
	pub := ed25519.PrivateKey(k[:]).Public().(ed25519.PublicKey)
	var p SignPubKey
	copy(p[:], pub)
	return p
}

// Verify reports whether sig is a valid signature of msg by the holder of the
// private key matching p.
func (p SignPubKey) Verify(msg, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(p[:]), msg, sig)
}

// String renders a signing public key as standard base64 — its text form in
// files and on the command line, and the display form of an owner identity.
func (p SignPubKey) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// String renders a signing private key as standard base64.
func (k SignKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// ParseSignPubKey parses the base64 text form produced by SignPubKey.String.
func ParseSignPubKey(s string) (SignPubKey, error) {
	var p SignPubKey
	if err := parseKey(s, p[:]); err != nil {
		return SignPubKey{}, fmt.Errorf("cap: parse signing public key: %w", err)
	}
	return p, nil
}

// ParseSignKey parses the base64 text form produced by SignKey.String.
func ParseSignKey(s string) (SignKey, error) {
	var k SignKey
	if err := parseKey(s, k[:]); err != nil {
		return SignKey{}, fmt.Errorf("cap: parse signing private key: %w", err)
	}
	return k, nil
}
