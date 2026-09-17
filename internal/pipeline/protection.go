package pipeline

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const EncryptionVersion uint8 = 1

var ErrInvalidCiphertext = errors.New("pipeline: invalid ciphertext")

type EncryptedChunk struct {
	Version    uint8
	Nonce      []byte
	Ciphertext []byte
}

func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func EncryptChunk(key, plaintext, associatedData []byte) (EncryptedChunk, error) {
	ciphertext, err := newGCM(key)
	if err != nil {
		return EncryptedChunk{}, err
	}
	nonce := make([]byte, ciphertext.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedChunk{}, err
	}
	return EncryptedChunk{Version: EncryptionVersion, Nonce: nonce, Ciphertext: ciphertext.Seal(nil, nonce, plaintext, associatedData)}, nil
}

func DecryptChunk(key []byte, chunk EncryptedChunk, associatedData []byte) ([]byte, error) {
	if chunk.Version != EncryptionVersion {
		return nil, ErrInvalidCiphertext
	}
	ciphertext, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(chunk.Nonce) != ciphertext.NonceSize() {
		return nil, ErrInvalidCiphertext
	}
	plaintext, err := ciphertext.Open(nil, chunk.Nonce, chunk.Ciphertext, associatedData)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("pipeline: encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
