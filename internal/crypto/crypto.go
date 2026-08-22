package crypto

// Package crypto provides encryption, key derivation, and key wrapping for Revika.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// KeyDerivation handles master key and per-file key derivation.
type KeyDerivation struct{}

// DeriveUserMasterKey derives a master key from a password using PBKDF2.
// Uses 100,000 iterations of PBKDF2-SHA256 with a random salt (generated if not provided).
func (kd *KeyDerivation) DeriveUserMasterKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	// Generate a random salt for this master key derivation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// PBKDF2-SHA256: 100,000 iterations, 32-byte output (256-bit)
	const iterations = 100000
	masterKey := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	if len(masterKey) != 32 {
		return nil, errors.New("derived key must be 32 bytes")
	}

	return masterKey, nil
}

// DerivePerFileKey derives a per-file key deterministically from master key and file content hash.
// Uses SHA256(master_key || file_content_hash) for deterministic derivation.
func (kd *KeyDerivation) DerivePerFileKey(masterKey []byte, fileContentHash [sha256.Size]byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("master key cannot be empty")
	}

	// Concatenate master key with file content hash
	h := sha256.New()
	h.Write(masterKey)
	h.Write(fileContentHash[:])

	// Return 32 bytes (256-bit) per-file key
	return h.Sum(nil), nil
}

// FileEncryption handles AES-256-GCM encryption and decryption of files.
type FileEncryption struct{}

// EncryptFile encrypts plaintext using AES-256-GCM.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
// Total overhead: 28 bytes (12 nonce + 16 tag)
func (fe *FileEncryption) EncryptFile(plaintext []byte, perFileKey []byte) ([]byte, error) {
	if len(perFileKey) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(perFileKey))
	}

	// Create AES cipher
	block, err := aes.NewCipher(perFileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and return nonce || ciphertext || tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptFile decrypts ciphertext encrypted by EncryptFile using AES-256-GCM.
// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
func (fe *FileEncryption) DecryptFile(ciphertext []byte, perFileKey []byte) ([]byte, error) {
	if len(perFileKey) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(perFileKey))
	}

	// Create AES cipher
	block, err := aes.NewCipher(perFileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length (nonce + tag)
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// KeyWrapping handles wrapping and unwrapping of per-file keys for sharing.
// Uses ECIES with X25519 for key exchange.
type KeyWrapping struct{}

// WrapKey encrypts a per-file key with recipient's public key using ECIES.
// Recipient public key is assumed to be a valid X25519 public key (32 bytes).
// Returns: ephemeral_public_key (32 bytes) || ciphertext || tag (16 bytes)
func (kw *KeyWrapping) WrapKey(perFileKey []byte, recipientPublicKey []byte) ([]byte, error) {
	if len(perFileKey) != 32 {
		return nil, fmt.Errorf("per-file key must be 32 bytes, got %d", len(perFileKey))
	}

	if len(recipientPublicKey) != 32 {
		return nil, fmt.Errorf("recipient public key must be 32 bytes (X25519), got %d", len(recipientPublicKey))
	}

	// Generate ephemeral X25519 keypair
	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}

	ephemeralPublicKeyBytes := ephemeralPrivateKey.PublicKey().Bytes()

	// Create recipient's public key for ECDH
	recipientPublicKeyObj, err := ecdh.X25519().NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := ephemeralPrivateKey.ECDH(recipientPublicKeyObj)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive symmetric key from shared secret using SHA-256
	// KDF: SHA256(shared_secret || "revika-keywrap")
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte("revika-keywrap"))
	symmetricKey := h.Sum(nil) // 32 bytes

	// Encrypt per-file key with derived symmetric key using AES-256-GCM
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce for GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt per-file key: ephemeral_pubkey || nonce || ciphertext || tag
	wrappedKeyContent := gcm.Seal(nonce, nonce, perFileKey, nil)

	// Return: ephemeral_public_key || nonce_and_ciphertext
	result := make([]byte, 0, 32+len(wrappedKeyContent))
	result = append(result, ephemeralPublicKeyBytes...)
	result = append(result, wrappedKeyContent...)

	return result, nil
}

// UnwrapKey decrypts a wrapped per-file key using device's private key.
// Wrapped key format: ephemeral_public_key (32 bytes) || nonce || ciphertext || tag (16 bytes)
func (kw *KeyWrapping) UnwrapKey(wrappedKey []byte, devicePrivateKey []byte) ([]byte, error) {
	if len(devicePrivateKey) != 32 {
		return nil, fmt.Errorf("device private key must be 32 bytes (X25519), got %d", len(devicePrivateKey))
	}

	// Minimum length: 32 (ephemeral pubkey) + 12 (nonce) + 16 (tag) = 60 bytes
	if len(wrappedKey) < 60 {
		return nil, errors.New("wrapped key too short")
	}

	// Extract ephemeral public key
	ephemeralPublicKeyBytes := wrappedKey[:32]
	encryptedContent := wrappedKey[32:]

	// Create device private key for ECDH
	devicePrivateKeyObj, err := ecdh.X25519().NewPrivateKey(devicePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid device private key: %w", err)
	}

	// Create ephemeral public key for ECDH
	ephemeralPublicKeyObj, err := ecdh.X25519().NewPublicKey(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := devicePrivateKeyObj.ECDH(ephemeralPublicKeyObj)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive symmetric key (same KDF as in WrapKey)
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte("revika-keywrap"))
	symmetricKey := h.Sum(nil) // 32 bytes

	// Create AES cipher
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedContent) < nonceSize {
		return nil, errors.New("encrypted content too short for nonce")
	}

	// Extract nonce and ciphertext
	nonce := encryptedContent[:nonceSize]
	ciphertext := encryptedContent[nonceSize:]

	// Decrypt
	perFileKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	return perFileKey, nil
}

// DeriveUserMasterKeyWithSalt is a helper for testing that accepts a specific salt.
// In production, use DeriveUserMasterKey which generates random salt.
func (kd *KeyDerivation) DeriveUserMasterKeyWithSalt(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	const iterations = 100000
	masterKey := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	if len(masterKey) != 32 {
		return nil, errors.New("derived key must be 32 bytes")
	}

	return masterKey, nil
}
