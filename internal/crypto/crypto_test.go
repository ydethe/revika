package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func mustKey(t *testing.T) Key {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := mustKey(t)
	for _, pt := range [][]byte{
		nil,
		{},
		[]byte("a"),
		[]byte("the quick brown fox"),
		bytes.Repeat([]byte{0xAB}, 4096),
	} {
		sealed, err := Seal(k, pt)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := Open(k, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	k := mustKey(t)
	pt := []byte("same plaintext")
	a, _ := Seal(k, pt)
	b, _ := Seal(k, pt)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of identical plaintext produced identical ciphertext (nonce reuse?)")
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	sealed, _ := Seal(k1, []byte("secret"))
	if _, err := Open(k2, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open with wrong key: got %v, want ErrDecrypt", err)
	}
}

func TestOpenTamperedFails(t *testing.T) {
	k := mustKey(t)
	sealed, _ := Seal(k, []byte("integrity matters"))
	// Flip a bit in every position; every mutation must be rejected.
	for i := range sealed {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 0x01
		if _, err := Open(k, tampered); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("tampering byte %d not detected: got %v", i, err)
		}
	}
}

func TestOpenTruncatedFails(t *testing.T) {
	k := mustKey(t)
	sealed, _ := Seal(k, []byte("data"))
	for n := 0; n < len(sealed); n++ {
		if _, err := Open(k, sealed[:n]); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("truncation to %d bytes not rejected: got %v", n, err)
		}
	}
}

// FuzzOpen ensures Open never panics on arbitrary input and never accepts it.
func FuzzOpen(f *testing.F) {
	k, err := NewKey()
	if err != nil {
		f.Fatalf("NewKey: %v", err)
	}
	// Seeds are deliberately NOT valid ciphertexts: Open must reject them all.
	// (Forging a valid GCM tag by chance is cryptographically infeasible.)
	f.Add([]byte{})
	f.Add(make([]byte, 12))  // nonce-sized, empty ciphertext
	f.Add(make([]byte, 128)) // random-ish zeros
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := Open(k, data); err == nil {
			t.Fatalf("Open accepted arbitrary %d-byte input", len(data))
		}
	})
}
