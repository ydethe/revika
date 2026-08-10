// Package atrest implements passphrase-based at-rest encryption for local
// workspace secrets (private key files and root.json) using Argon2id as KDF
// and AES-256-GCM as AEAD — both mandated by the project's PQC-safe crypto
// baseline.
//
// Encrypted files share a stable wire format so tools can distinguish them from
// legacy plaintext files and migrate transparently:
//
//	magic(8) | salt(16) | nonce(12) | AES-256-GCM(plaintext) | GCM-tag(16)
//
// The magic is "rvk-enc\x01": seven ASCII bytes plus a one-byte format version.
// A file that does not start with the magic is treated as plaintext, enabling
// old workspaces to continue working without re-keying.
//
// KDF parameters match DefaultArgon2id() in internal/cap: t=2, m=64 MiB, p=1.
// These are deliberately conservative for an interactive CLI (tens of
// milliseconds on a current CPU), while still brute-force-resistant for a
// 128-bit-entropy passphrase.
//
// Defence controls (security/Defence.md; primitive P3 in security/frameworks.md):
//
//	SC-28 (Protection of Information at Rest) — AES-256-GCM seals secrets so
//	      disk access (backup, imaging, directory traversal) does not expose keys.
//	IA-5  (Authenticator Management)          — GCM authentication catches both
//	      wrong passphrases and tampered files in a single constant-time check.
package atrest

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "fmt"

    "golang.org/x/crypto/argon2"
)

// magic is the eight-byte prefix of every encrypted file. The trailing \x01
// is a format version; bump it if the wire layout ever changes incompatibly.
var magic = []byte("rvk-enc\x01")

// overhead is the fixed byte cost beyond the ciphertext: magic + salt + nonce + GCM tag.
const overhead = 8 + 16 + 12 + 16

// ErrBadPassphrase is returned by Decrypt when GCM authentication fails,
// meaning the passphrase is wrong or the file is tampered.
var ErrBadPassphrase = errors.New("atrest: wrong passphrase or corrupted file")

// IsEncrypted reports whether b starts with the magic prefix — i.e. was written
// by Encrypt and must be opened with Decrypt rather than used as-is.
func IsEncrypted(b []byte) bool {
    return bytes.HasPrefix(b, magic)
}

// Encrypt seals plaintext under passphrase. Each call generates a fresh
// 16-byte salt and 12-byte nonce, so two calls with the same inputs produce
// distinct ciphertexts. The output can be passed directly to Decrypt.
func Encrypt(plaintext, passphrase []byte) ([]byte, error) {
    var salt [16]byte
    if _, err := rand.Read(salt[:]); err != nil {
        return nil, fmt.Errorf("atrest: generate salt: %w", err)
    }
    var nonce [12]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        return nil, fmt.Errorf("atrest: generate nonce: %w", err)
    }

    key := kdf(passphrase, salt[:])
    gcm, err := newGCM(key)
    if err != nil {
        return nil, err
    }

    ct := gcm.Seal(nil, nonce[:], plaintext, magic)
    out := make([]byte, 0, overhead+len(plaintext))
    out = append(out, magic...)
    out = append(out, salt[:]...)
    out = append(out, nonce[:]...)
    return append(out, ct...), nil
}

// Decrypt opens a blob produced by Encrypt. It returns ErrBadPassphrase when
// the passphrase is wrong or the file is corrupt. A blob that does not start
// with the magic is returned as-is (plaintext pass-through for migration).
func Decrypt(ciphertext, passphrase []byte) ([]byte, error) {
    if !IsEncrypted(ciphertext) {
        return ciphertext, nil
    }
    if len(ciphertext) < overhead {
        return nil, fmt.Errorf("atrest: encrypted file is too short (%d bytes)", len(ciphertext))
    }
    salt := ciphertext[8:24]
    nonce := ciphertext[24:36]
    ct := ciphertext[36:]

    key := kdf(passphrase, salt)
    gcm, err := newGCM(key)
    if err != nil {
        return nil, err
    }

    plain, err := gcm.Open(nil, nonce, ct, magic)
    if err != nil {
        return nil, ErrBadPassphrase
    }
    return plain, nil
}

func kdf(passphrase, salt []byte) []byte {
    return argon2.IDKey(passphrase, salt, 2, 64*1024, 1, 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("atrest: init cipher: %w", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("atrest: init GCM: %w", err)
    }
    return gcm, nil
}
