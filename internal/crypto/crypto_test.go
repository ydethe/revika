package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestKeyDerivationDeriveUserMasterKey(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid password",
			password: "mypassword123",
			wantErr:  false,
		},
		{
			name:     "long password",
			password: "this is a very long and complex password with special chars !@#$%",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
			errMsg:   "password cannot be empty",
		},
	}

	kd := &KeyDerivation{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := kd.DeriveUserMasterKey(tt.password)

			if (err != nil) != tt.wantErr {
				t.Fatalf("DeriveUserMasterKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err.Error() != tt.errMsg {
				t.Fatalf("DeriveUserMasterKey() error = %v, want %v", err.Error(), tt.errMsg)
			}

			if !tt.wantErr {
				if len(key) != 32 {
					t.Fatalf("expected 32-byte key, got %d", len(key))
				}
			}
		})
	}
}

func TestKeyDerivationDeriveUserMasterKeyDeterministic(t *testing.T) {
	kd := &KeyDerivation{}
	password := "test-password"
	salt := make([]byte, 16)
	copy(salt, []byte("fixed-salt-test-"))

	key1, err := kd.DeriveUserMasterKeyWithSalt(password, salt)
	if err != nil {
		t.Fatalf("DeriveUserMasterKeyWithSalt failed: %v", err)
	}

	key2, err := kd.DeriveUserMasterKeyWithSalt(password, salt)
	if err != nil {
		t.Fatalf("DeriveUserMasterKeyWithSalt failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password and salt should produce same key")
	}
}

func TestKeyDerivationDerivePerFileKey(t *testing.T) {
	kd := &KeyDerivation{}
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	fileHash1 := sha256.Sum256([]byte("file1.txt"))
	fileHash2 := sha256.Sum256([]byte("file2.txt"))

	key1, err := kd.DerivePerFileKey(masterKey, fileHash1)
	if err != nil {
		t.Fatalf("DerivePerFileKey failed: %v", err)
	}

	key2, err := kd.DerivePerFileKey(masterKey, fileHash2)
	if err != nil {
		t.Fatalf("DerivePerFileKey failed: %v", err)
	}

	// Different files should produce different keys
	if bytes.Equal(key1, key2) {
		t.Fatal("different file hashes should produce different keys")
	}

	// Same file should produce same key (deterministic)
	key1Again, err := kd.DerivePerFileKey(masterKey, fileHash1)
	if err != nil {
		t.Fatalf("DerivePerFileKey failed: %v", err)
	}

	if !bytes.Equal(key1, key1Again) {
		t.Fatal("same master key and file hash should produce same key")
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}
}

func TestKeyDerivationDerivePerFileKeyErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		masterKey   []byte
		fileHash    [32]byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty master key",
			masterKey:   []byte{},
			fileHash:    sha256.Sum256([]byte("test")),
			wantErr:     true,
			errContains: "master key cannot be empty",
		},
	}

	kd := &KeyDerivation{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kd.DerivePerFileKey(tt.masterKey, tt.fileHash)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DerivePerFileKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err.Error() != tt.errContains {
				t.Fatalf("DerivePerFileKey() error = %v, want %v", err.Error(), tt.errContains)
			}
		})
	}
}

func TestFileEncryptionRoundtrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "empty data",
			plaintext: []byte{},
		},
		{
			name:      "small data",
			plaintext: []byte("hello world"),
		},
		{
			name:      "1MB data",
			plaintext: make([]byte, 1024*1024),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0xFF, 0x01, 0xFE, 0x80, 0x7F},
		},
	}

	fe := &FileEncryption{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill random data for 1MB test
			if len(tt.plaintext) == 1024*1024 {
				rand.Read(tt.plaintext)
			}

			key := make([]byte, 32)
			rand.Read(key)

			// Encrypt
			ciphertext, err := fe.EncryptFile(tt.plaintext, key)
			if err != nil {
				t.Fatalf("EncryptFile failed: %v", err)
			}

			// Verify overhead: 12 (nonce) + 16 (tag)
			if len(ciphertext) != len(tt.plaintext)+28 {
				t.Fatalf("expected ciphertext length %d, got %d", len(tt.plaintext)+28, len(ciphertext))
			}

			// Decrypt
			decrypted, err := fe.DecryptFile(ciphertext, key)
			if err != nil {
				t.Fatalf("DecryptFile failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Fatal("decrypted data does not match plaintext")
			}
		})
	}
}

func TestFileEncryptionDecryptionFails(t *testing.T) {
	tests := []struct {
		name       string
		setupFunc  func() ([]byte, []byte)
		wantErrMsg string
	}{
		{
			name: "wrong key",
			setupFunc: func() ([]byte, []byte) {
				fe := &FileEncryption{}
				plaintext := []byte("secret data")
				key1 := make([]byte, 32)
				key2 := make([]byte, 32)
				rand.Read(key1)
				rand.Read(key2)

				ciphertext, _ := fe.EncryptFile(plaintext, key1)
				return ciphertext, key2
			},
			wantErrMsg: "decryption failed",
		},
		{
			name: "corrupted ciphertext",
			setupFunc: func() ([]byte, []byte) {
				fe := &FileEncryption{}
				plaintext := []byte("secret data")
				key := make([]byte, 32)
				rand.Read(key)

				ciphertext, _ := fe.EncryptFile(plaintext, key)
				// Flip a bit in the ciphertext
				ciphertext[32] ^= 0xFF
				return ciphertext, key
			},
			wantErrMsg: "decryption failed",
		},
		{
			name: "too short ciphertext",
			setupFunc: func() ([]byte, []byte) {
				key := make([]byte, 32)
				rand.Read(key)
				return []byte{1, 2, 3}, key
			},
			wantErrMsg: "ciphertext too short",
		},
	}

	fe := &FileEncryption{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, key := tt.setupFunc()
			_, err := fe.DecryptFile(ciphertext, key)
			if err == nil {
				t.Fatal("expected decryption to fail")
			}
			if err.Error() != tt.wantErrMsg {
				t.Fatalf("expected error %q, got %q", tt.wantErrMsg, err.Error())
			}
		})
	}
}

func TestFileEncryptionKeySize(t *testing.T) {
	fe := &FileEncryption{}
	plaintext := []byte("test data")

	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{name: "correct key size", keySize: 32, wantErr: false},
		{name: "too small key", keySize: 16, wantErr: true},
		{name: "too large key", keySize: 64, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			rand.Read(key)

			_, err := fe.EncryptFile(plaintext, key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncryptFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeyWrappingRoundtrip(t *testing.T) {
	kw := &KeyWrapping{}

	// Generate device keypair (X25519)
	devicePrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate device keypair: %v", err)
	}
	devicePrivateKeyBytes := devicePrivateKey.Bytes()
	devicePublicKeyBytes := devicePrivateKey.PublicKey().Bytes()

	tests := []struct {
		name        string
		perFileKey  []byte
		recipientPK []byte
		wantErr     bool
	}{
		{
			name:        "valid wrap/unwrap",
			perFileKey:  makeFixedKey(32),
			recipientPK: devicePublicKeyBytes,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap the key
			wrappedKey, err := kw.WrapKey(tt.perFileKey, tt.recipientPK)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WrapKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			// Verify structure: 32 (ephemeral pubkey) + 12 (nonce) + len + 16 (tag)
			if len(wrappedKey) < 60 {
				t.Fatalf("wrapped key too short: %d", len(wrappedKey))
			}

			// Unwrap with device private key
			unwrappedKey, err := kw.UnwrapKey(wrappedKey, devicePrivateKeyBytes)
			if err != nil {
				t.Fatalf("UnwrapKey() failed: %v", err)
			}

			// Verify the unwrapped key matches the original
			if !bytes.Equal(unwrappedKey, tt.perFileKey) {
				t.Fatal("unwrapped key does not match original")
			}
		})
	}
}

func TestKeyWrappingErrorCases(t *testing.T) {
	kw := &KeyWrapping{}

	tests := []struct {
		name           string
		perFileKey     []byte
		recipientPK    []byte
		wantErr        bool
		errContains    string
		testUnwrap     bool
		unwrapKey      []byte
		devicePrivateK []byte
	}{
		{
			name:        "wrong perFileKey size",
			perFileKey:  make([]byte, 16),
			recipientPK: makeFixedKey(32),
			wantErr:     true,
			errContains: "per-file key must be 32 bytes",
		},
		{
			name:        "wrong recipient key size",
			perFileKey:  makeFixedKey(32),
			recipientPK: make([]byte, 16),
			wantErr:     true,
			errContains: "recipient public key must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kw.WrapKey(tt.perFileKey, tt.recipientPK)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WrapKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
				t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}

func TestKeyWrappingUnwrapErrors(t *testing.T) {
	kw := &KeyWrapping{}

	tests := []struct {
		name           string
		wrappedKey     []byte
		devicePrivateK []byte
		wantErr        bool
		errContains    string
	}{
		{
			name:           "wrapped key too short",
			wrappedKey:     make([]byte, 20),
			devicePrivateK: makeFixedKey(32),
			wantErr:        true,
			errContains:    "wrapped key too short",
		},
		{
			name:           "wrong device key size",
			wrappedKey:     make([]byte, 60),
			devicePrivateK: make([]byte, 16),
			wantErr:        true,
			errContains:    "device private key must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kw.UnwrapKey(tt.wrappedKey, tt.devicePrivateK)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnwrapKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
				t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}

// Helper function to create fixed keys for testing
func makeFixedKey(size int) []byte {
	key := make([]byte, size)
	for i := 0; i < size; i++ {
		key[i] = byte(i % 256)
	}
	return key
}

// TestKeyWrappingWithDifferentRecipients verifies that wrapping with different recipient keys
// produces different wrapped keys, even for the same per-file key.
func TestKeyWrappingWithDifferentRecipients(t *testing.T) {
	kw := &KeyWrapping{}

	// Generate two different recipient keypairs
	recipient1Private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient1 keypair: %v", err)
	}
	recipient1Public := recipient1Private.PublicKey().Bytes()

	recipient2Private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient2 keypair: %v", err)
	}
	recipient2Public := recipient2Private.PublicKey().Bytes()

	perFileKey := makeFixedKey(32)

	// Wrap same key for different recipients
	wrapped1, err := kw.WrapKey(perFileKey, recipient1Public)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	wrapped2, err := kw.WrapKey(perFileKey, recipient2Public)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Wrapped keys should be different (because ephemeral key is random)
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("wrapped keys for different recipients should be different")
	}

	// Each recipient should only be able to unwrap their own wrapped key
	device1PrivateKeyBytes := recipient1Private.Bytes()
	device2PrivateKeyBytes := recipient2Private.Bytes()

	unwrapped1, err := kw.UnwrapKey(wrapped1, device1PrivateKeyBytes)
	if err != nil {
		t.Fatalf("UnwrapKey with correct key failed: %v", err)
	}

	if !bytes.Equal(unwrapped1, perFileKey) {
		t.Fatal("recipient1 should unwrap to correct key")
	}

	// Recipient2 cannot unwrap wrapped1
	_, err = kw.UnwrapKey(wrapped1, device2PrivateKeyBytes)
	if err == nil {
		t.Fatal("recipient2 should not be able to unwrap wrapped1")
	}
}

// TestKeyWrappingDeterminismWithEphemeral verifies that wrapping is non-deterministic
// due to ephemeral key generation and random nonce, which is correct for security.
func TestKeyWrappingNonDeterminism(t *testing.T) {
	kw := &KeyWrapping{}

	recipientPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient keypair: %v", err)
	}
	recipientPublicKeyBytes := recipientPrivateKey.PublicKey().Bytes()

	perFileKey := makeFixedKey(32)

	// Wrap same key twice
	wrapped1, err := kw.WrapKey(perFileKey, recipientPublicKeyBytes)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	wrapped2, err := kw.WrapKey(perFileKey, recipientPublicKeyBytes)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Wrapped keys should be different (ephemeral key + nonce are random)
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("wrapping same key twice should produce different results (non-deterministic)")
	}

	// But both should unwrap to same key
	devicePrivateKeyBytes := recipientPrivateKey.Bytes()

	unwrapped1, err := kw.UnwrapKey(wrapped1, devicePrivateKeyBytes)
	if err != nil {
		t.Fatalf("UnwrapKey failed: %v", err)
	}

	unwrapped2, err := kw.UnwrapKey(wrapped2, devicePrivateKeyBytes)
	if err != nil {
		t.Fatalf("UnwrapKey failed: %v", err)
	}

	if !bytes.Equal(unwrapped1, perFileKey) || !bytes.Equal(unwrapped2, perFileKey) {
		t.Fatal("both should unwrap to same original key")
	}
}
