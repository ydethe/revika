package pipeline

import (
	"bytes"
	"testing"
)

func TestEncryptedChunkRoundTripAndAuthentication(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	want := []byte("encrypted chunk")
	chunk, err := EncryptChunk(key, want, []byte("manifest-id"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptChunk(key, chunk, []byte("manifest-id"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("DecryptChunk = %q, %v", got, err)
	}
	chunk.Ciphertext[0] ^= 1
	if _, err := DecryptChunk(key, chunk, []byte("manifest-id")); err != ErrInvalidCiphertext {
		t.Fatalf("tampered ciphertext error = %v, want ErrInvalidCiphertext", err)
	}
}
