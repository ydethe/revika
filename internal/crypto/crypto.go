// Package crypto provides the client-side authenticated encryption used before
// any bytes leave a User's machine. Each object (chunk) is sealed under a fresh
// random key with AES-256-GCM, so nodes only ever store ciphertext they cannot
// read and cannot tamper with undetected.
//
// AES-256-GCM is used purely from the standard library (crypto/aes,
// crypto/cipher) to avoid an external dependency. The 12-byte random nonce is
// prepended to the ciphertext; GCM's authentication tag is appended by Seal.
//
// Defence controls (security/Defence.md; primitive P1 in security/frameworks.md):
//   D3-MENCR (Message Encryption)               — AES-256-GCM AEAD seals every chunk client-side.
//   SC-28    (Protection of Information at Rest) — nodes only ever hold ciphertext at rest.
//   SC-13    (Cryptographic Protection)          — AES-256 (PQC-safe), stdlib only.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// ErrDecrypt is returned by Open when authentication fails (wrong key, or
// tampered/truncated ciphertext). It never distinguishes the cause, by design.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Key is a 256-bit symmetric key.
type Key [KeySize]byte

// NewKey returns a fresh random key from the OS CSPRNG.
func NewKey() (Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return Key{}, fmt.Errorf("crypto: generate key: %w", err)
	}
	return k, nil
}

func aead(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return g, nil
}

// Seal encrypts plaintext under k, returning nonce||ciphertext||tag. Each call
// uses a fresh random nonce, so sealing identical plaintext twice yields
// distinct outputs.
func Seal(k Key, plaintext []byte) ([]byte, error) {
	g, err := aead(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	// Seal appends the ciphertext to nonce, so the nonce prefixes the result.
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. It returns ErrDecrypt if authentication fails for any
// reason.
func Open(k Key, sealed []byte) ([]byte, error) {
	g, err := aead(k)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(sealed) < ns {
		return nil, ErrDecrypt
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
