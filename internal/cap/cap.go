// Package cap is revika's capability-delivery layer: it wraps a serialized
// read-capability (in practice, a file's manifest bytes) so that only the
// holder of a chosen recipient's private key can unwrap it.
//
// This is the mechanism behind sharing (Architecture
// §3.5): access is granted by handing over a read-cap, and cap delivery is done
// by encrypting that cap to the recipient's public key. Nodes are never
// involved and learn nothing — wrapping and unwrapping are purely client-side.
//
// Crypto. Recipients are identified by an ML-KEM-768 keypair (NIST FIPS 203,
// the post-quantum key-encapsulation mechanism formerly known as Kyber), from
// the crypto/mlkem standard library. Wrap is a KEM-DEM construction:
// Encapsulate against the recipient's public (encapsulation) key yields a fresh
// random shared secret plus a KEM ciphertext, and that shared secret keys an
// AES-256-GCM seal of the payload (the DEM, reused from internal/crypto — AES-256
// is itself quantum-resistant). Every Wrap draws fresh encapsulation randomness,
// so the wrapped cap carries no sender identity and cannot be linked across
// shares. Unwrap decapsulates with the recipient's private key to recover the
// same secret. cap does not know what it is wrapping — it moves opaque bytes —
// so the read-cap serialization can evolve independently.
package cap

import (
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"

	"revika/internal/crypto"
)

// Key sizes, from the ML-KEM-768 parameter set (FIPS 203).
const (
	// PublicKeySize is the length in bytes of an ML-KEM-768 encapsulation key.
	PublicKeySize = mlkem.EncapsulationKeySize768 // 1184
	// PrivateKeySize is the length in bytes of the seed ("d || z") from which an
	// ML-KEM-768 decapsulation key is deterministically expanded.
	PrivateKeySize = mlkem.SeedSize // 64
)

// ErrUnwrap is returned by Unwrap when the sealed cap cannot be opened: wrong
// recipient key, or tampered/truncated ciphertext. Like crypto.ErrDecrypt it
// never distinguishes the cause, by design. (ML-KEM decapsulation itself never
// reports a wrong key — it returns a mismatched secret via implicit rejection —
// so the failure surfaces at the AES-256-GCM authentication check.)
var ErrUnwrap = errors.New("cap: unwrap failed")

// PublicKey identifies a recipient; it is safe to share and is what a sender
// wraps a capability to. It is a raw ML-KEM-768 encapsulation key.
type PublicKey [PublicKeySize]byte

// PrivateKey is a recipient's secret; whoever holds it can unwrap caps sent to
// the matching PublicKey. Keep it secret. It is the 64-byte ML-KEM-768 seed,
// from which the full decapsulation key is expanded on demand.
type PrivateKey [PrivateKeySize]byte

// GenerateIdentity returns a fresh ML-KEM-768 keypair from the OS CSPRNG.
func GenerateIdentity() (PrivateKey, PublicKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("cap: generate identity: %w", err)
	}
	var priv PrivateKey
	var pub PublicKey
	copy(priv[:], dk.Bytes())
	copy(pub[:], dk.EncapsulationKey().Bytes())
	return priv, pub, nil
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

// Wrap seals plaintext to recipient with a fresh ML-KEM encapsulation, returning
// a sealed cap (KEM ciphertext || AES-256-GCM ciphertext) that only the
// recipient's private key can open. Sealing the same plaintext twice yields
// distinct outputs (fresh encapsulation randomness and AES-GCM nonce each call).
func Wrap(recipient PublicKey, plaintext []byte) ([]byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(recipient[:])
	if err != nil {
		return nil, fmt.Errorf("cap: wrap: %w", err)
	}
	sharedKey, kemCiphertext := ek.Encapsulate()
	var key crypto.Key
	copy(key[:], sharedKey)
	dem, err := crypto.Seal(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("cap: wrap: %w", err)
	}
	sealed := make([]byte, 0, len(kemCiphertext)+len(dem))
	sealed = append(sealed, kemCiphertext...)
	sealed = append(sealed, dem...)
	return sealed, nil
}

// Unwrap opens a sealed cap with the recipient's private key, returning the
// original plaintext or ErrUnwrap. pub is accepted for API symmetry but is not
// needed: ML-KEM decapsulation uses only the private key.
func Unwrap(priv PrivateKey, pub PublicKey, sealed []byte) ([]byte, error) {
	_ = pub
	if len(sealed) < mlkem.CiphertextSize768 {
		return nil, ErrUnwrap
	}
	dk, err := mlkem.NewDecapsulationKey768(priv[:])
	if err != nil {
		return nil, ErrUnwrap
	}
	kemCiphertext, dem := sealed[:mlkem.CiphertextSize768], sealed[mlkem.CiphertextSize768:]
	sharedKey, err := dk.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, ErrUnwrap
	}
	var key crypto.Key
	copy(key[:], sharedKey)
	plaintext, err := crypto.Open(key, dem)
	if err != nil {
		return nil, ErrUnwrap
	}
	return plaintext, nil
}

// Public derives the public key matching a private key, so a caller that stored
// only the private key can still name their own recipient identity. It expands
// the ML-KEM-768 decapsulation key from the seed and returns its encapsulation
// key; the mapping is deterministic, so it always reproduces the paired public
// key.
func (k PrivateKey) Public() (PublicKey, error) {
	dk, err := mlkem.NewDecapsulationKey768(k[:])
	if err != nil {
		return PublicKey{}, fmt.Errorf("cap: derive public key: %w", err)
	}
	var pub PublicKey
	copy(pub[:], dk.EncapsulationKey().Bytes())
	return pub, nil
}
