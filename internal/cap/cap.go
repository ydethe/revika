// Package cap is revika's capability-delivery layer: it wraps a serialized
// read-capability (in practice, a file's manifest bytes) so that only the
// holder of a chosen recipient's private key can unwrap it.
//
// This is the mechanism behind sharing in the Tahoe-LAFS model (Architecture
// §3.5): access is granted by handing over a read-cap, and cap delivery is done
// by encrypting that cap to the recipient's public key. Nodes are never
// involved and learn nothing — wrapping and unwrapping are purely client-side.
//
// Crypto. Recipients are identified by an X25519 (Curve25519) keypair. Wrap
// uses NaCl box's anonymous sealing: an ephemeral sender keypair is generated
// per message, so the wrapped cap carries no sender identity and cannot be
// linked across shares. Unwrap requires the recipient's private key. cap does
// not know what it is wrapping — it moves opaque bytes — so the read-cap
// serialization can evolve independently.
package cap

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// KeySize is the length in bytes of an X25519 public or private key.
const KeySize = 32

// ErrUnwrap is returned by Unwrap when the sealed cap cannot be opened: wrong
// recipient key, or tampered/truncated ciphertext. Like crypto.ErrDecrypt it
// never distinguishes the cause, by design.
var ErrUnwrap = errors.New("cap: unwrap failed")

// PublicKey identifies a recipient; it is safe to share and is what a sender
// wraps a capability to.
type PublicKey [KeySize]byte

// PrivateKey is a recipient's secret; whoever holds it can unwrap caps sent to
// the matching PublicKey. Keep it secret.
type PrivateKey [KeySize]byte

// GenerateIdentity returns a fresh X25519 keypair from the OS CSPRNG.
func GenerateIdentity() (PrivateKey, PublicKey, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("cap: generate identity: %w", err)
	}
	return PrivateKey(*priv), PublicKey(*pub), nil
}

// String renders a public key as standard base64, the text form used in files
// and on the command line.
func (k PublicKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// String renders a private key as standard base64.
func (k PrivateKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// ParsePublicKey parses the base64 text form produced by PublicKey.String.
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	if err := parseKey(s, k[:]); err != nil {
		return PublicKey{}, fmt.Errorf("cap: parse public key: %w", err)
	}
	return k, nil
}

// ParsePrivateKey parses the base64 text form produced by PrivateKey.String.
func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	if err := parseKey(s, k[:]); err != nil {
		return PrivateKey{}, fmt.Errorf("cap: parse private key: %w", err)
	}
	return k, nil
}

func parseKey(s string, dst []byte) error {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(raw) != len(dst) {
		return fmt.Errorf("want %d bytes, got %d", len(dst), len(raw))
	}
	copy(dst, raw)
	return nil
}

// Wrap seals plaintext to recipient using an ephemeral sender key, returning a
// sealed cap that only the recipient's private key can open. Sealing the same
// plaintext twice yields distinct outputs (fresh ephemeral key each call).
func Wrap(recipient PublicKey, plaintext []byte) ([]byte, error) {
	rpub := [KeySize]byte(recipient)
	sealed, err := box.SealAnonymous(nil, plaintext, &rpub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cap: wrap: %w", err)
	}
	return sealed, nil
}

// Unwrap opens a sealed cap with the recipient's keypair, returning the original
// plaintext or ErrUnwrap. The public key must be the one matching priv; it is
// required by the anonymous-box construction to recover the ephemeral shared
// secret.
func Unwrap(priv PrivateKey, pub PublicKey, sealed []byte) ([]byte, error) {
	rpub := [KeySize]byte(pub)
	rpriv := [KeySize]byte(priv)
	plaintext, ok := box.OpenAnonymous(nil, sealed, &rpub, &rpriv)
	if !ok {
		return nil, ErrUnwrap
	}
	return plaintext, nil
}

// Public derives the public key matching a private key, so a caller that stored
// only the private key can still unwrap (which needs both). It is X25519
// base-point scalar multiplication.
func (k PrivateKey) Public() (PublicKey, error) {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return PublicKey{}, fmt.Errorf("cap: derive public key: %w", err)
	}
	return PublicKey(pub), nil
}
