# `internal/crypto` Package

**Purpose**: End-to-end encryption, key derivation, and key wrapping for Revika's client-side encryption model.

## Overview

The `crypto` package provides all cryptographic primitives needed for Revika to operate as an end-to-end encrypted system. Users encrypt data locally before it ever leaves their machine; nodes store ciphertext and cannot read content.

## Design Decisions

### 1. Master Key Derivation (PBKDF2-SHA256)

```go
DeriveUserMasterKey(password string) -> 256-bit key
```

- **Algorithm**: PBKDF2-SHA256 with 100,000 iterations
- **Output**: 32 bytes (256 bits)
- **Why**: PBKDF2 is NIST-approved, resistant to GPU/ASIC attacks, and audited in production systems
- **Salt**: Randomly generated; Phase 1 assumes caller stores/manages it (Phase 3 will use OS keychain)
- **Iterations**: 100k matches OWASP recommendations as of 2024

**Note**: Phase 1 does not handle master key storage; Phase 3 will integrate OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).

### 2. Per-File Key Derivation (SHA256-based KDF)

```go
DerivePerFileKey(masterKey, fileContentHash) -> 256-bit per-file key
```

- **Algorithm**: SHA256(master_key || file_content_hash)
- **Output**: 32 bytes (256 bits)
- **Why**: 
  - Deterministic: Same file always produces same key
  - Different files produce different keys
  - Efficient: Single SHA256 operation
  - Compatible with sharing: Recipient receives wrapped per-file key, not master key

**Property**: If two users have the same master key and encrypt the same file, they produce the same ciphertext. This is acceptable for Phase 1; Phase 3 may add ephemeral randomness.

### 3. File Encryption (AES-256-GCM)

```go
EncryptFile(plaintext, perFileKey) -> nonce (12B) || ciphertext || tag (16B)
```

- **Algorithm**: AES-256-GCM with random nonce
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 12 bytes, randomly generated per encryption (ensures non-deterministic ciphertext)
- **Tag**: 16 bytes (AEAD authentication tag)
- **Why**:
  - AES-256-GCM is NIST-approved, AEAD-authenticated, standard in TLS 1.3
  - Random nonce prevents ciphertext patterns even for repeated plaintexts
  - Authentication tag detects tampering

**Note**: Ciphertext is non-deterministic due to random nonce. Shards created from same plaintext will have different encrypted bytes (but same shard IDs post-derivation would differ).

### 4. Key Wrapping (ECIES with X25519)

```go
WrapKey(perFileKey, recipientPublicKey) -> wrapped_key
UnwrapKey(wrappedKey, devicePrivateKey) -> per_file_key
```

- **Algorithm**: ECIES (Elliptic Curve Integrated Encryption Scheme)
- **Key Exchange**: X25519 ECDH with ephemeral keypair
- **KDF**: SHA256(shared_secret || "revika-keywrap")
- **Symmetric Encryption**: AES-256-GCM
- **Why**:
  - X25519 is modern, fast, safe against implementation errors
  - Ephemeral keypair provides perfect forward secrecy
  - ECIES is standard for hybrid encryption (combines asymmetric + symmetric)
  - No need for certificates; public keys exchanged manually in Phase 1 (Phase 3: TBD)

**Output Format**: `ephemeral_pubkey (32B) || nonce (12B) || ciphertext || tag (16B)`

**Security**: Recipient's private key is never exposed; only ephemeral public key and encrypted key are transmitted.

## Usage Examples

### Example 1: Encrypt and Store a File

```go
package main

import (
	"crypto/sha256"
	"github.com/revika/revika/internal/crypto"
)

func encryptAndStore(plaintext []byte, password string) ([]byte, error) {
	// Step 1: Derive master key from password
	kd := &crypto.KeyDerivation{}
	masterKey, err := kd.DeriveUserMasterKey(password)
	if err != nil {
		return nil, err
	}

	// Step 2: Derive per-file key deterministically
	fileHash := sha256.Sum256(plaintext)
	perFileKey, err := kd.DerivePerFileKey(masterKey, fileHash)
	if err != nil {
		return nil, err
	}

	// Step 3: Encrypt file
	fe := &crypto.FileEncryption{}
	ciphertext, err := fe.EncryptFile(plaintext, perFileKey)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
```

### Example 2: Share a File with Another User

```go
func shareFileWithRecipient(perFileKey []byte, recipientPublicKey []byte) ([]byte, error) {
	// Wrap per-file key with recipient's public key
	kw := &crypto.KeyWrapping{}
	wrappedKey, err := kw.WrapKey(perFileKey, recipientPublicKey)
	if err != nil {
		return nil, err
	}

	// Send wrappedKey to recipient via secure channel
	// Recipient uses their private key to unwrap and decrypt file
	return wrappedKey, nil
}
```

### Example 3: Recipient Receives Shared File

```go
func recipientUnwrapsAndDecrypts(wrappedKey []byte, devicePrivateKey []byte, 
	ciphertext []byte) ([]byte, error) {
	
	// Step 1: Unwrap per-file key using device's private key
	kw := &crypto.KeyWrapping{}
	perFileKey, err := kw.UnwrapKey(wrappedKey, devicePrivateKey)
	if err != nil {
		return nil, err
	}

	// Step 2: Decrypt file
	fe := &crypto.FileEncryption{}
	plaintext, err := fe.DecryptFile(ciphertext, perFileKey)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
```

## Exported Types & Functions

| Type | Purpose |
|------|---------|
| `KeyDerivation` | Master key and per-file key derivation |
| `FileEncryption` | File encryption and decryption |
| `KeyWrapping` | Key wrapping for sharing and unwrapping for recipients |

| Function | Purpose |
|----------|---------|
| `KeyDerivation.DeriveUserMasterKey(password)` | Derive 256-bit master key from password |
| `KeyDerivation.DerivePerFileKey(masterKey, fileHash)` | Derive 256-bit per-file key deterministically |
| `FileEncryption.EncryptFile(plaintext, perFileKey)` | Encrypt file with AES-256-GCM |
| `FileEncryption.DecryptFile(ciphertext, perFileKey)` | Decrypt file |
| `KeyWrapping.WrapKey(perFileKey, recipientPublicKey)` | Wrap per-file key for recipient |
| `KeyWrapping.UnwrapKey(wrappedKey, devicePrivateKey)` | Unwrap per-file key |

## Security Properties

1. **Master Key Isolation**: Master key is never transmitted; only per-file keys are shared (wrapped)
2. **Per-File Key Determinism**: Same file + master key = same per-file key (enables deduplication, but see Phase 3 for randomness option)
3. **Ciphertext Non-Determinism**: Random nonce in AES-GCM ensures different ciphertexts for same plaintext
4. **Forward Secrecy**: Ephemeral keys in ECIES key wrapping provide forward secrecy
5. **Authentication**: GCM mode provides authentication; tampering is detected
6. **Opaque Decryption Errors**: `DecryptFile` and `UnwrapKey` return a static `"decryption failed"` error and never wrap the underlying AES-GCM authentication failure, so GCM internals do not leak to callers and failure modes are indistinguishable to an attacker

## Testing

Run tests:
```bash
go test ./internal/crypto/ -v
```

Test coverage includes:
- Master key derivation with different password lengths
- Per-file key determinism (same inputs = same output)
- Encryption/decryption roundtrips for various file sizes
- Decryption error cases (wrong key, corrupted ciphertext, truncated data)
- Key wrapping with different recipients
- Key wrapping non-determinism (ephemeral + nonce randomness)
- Cross-recipient key isolation

## Deferred to Future Phases

- **Master key storage**: Phase 3 will integrate OS keychain
- **Master key rotation**: TBD (may require re-encryption of all per-file keys)
- **Key agreement protocol**: Phase 3 will handle public key exchange (currently manual)
- **Threshold encryption**: Phase 4+ for multi-signature ledger consensus
- **Post-quantum cryptography**: Future-proofing if needed
