package atrest

import (
    "bytes"
    "errors"
    "testing"
)

func TestRoundTrip(t *testing.T) {
    plain := []byte("secret key material that must survive round trip")
    pass := []byte("hunter2")

    ct, err := Encrypt(plain, pass)
    if err != nil {
        t.Fatalf("Encrypt: %v", err)
    }
    if !IsEncrypted(ct) {
        t.Fatal("IsEncrypted = false for Encrypt output")
    }
    if len(ct) < overhead {
        t.Fatalf("ciphertext too short: %d < %d", len(ct), overhead)
    }

    got, err := Decrypt(ct, pass)
    if err != nil {
        t.Fatalf("Decrypt: %v", err)
    }
    if !bytes.Equal(got, plain) {
        t.Fatalf("round-trip mismatch: got %q, want %q", got, plain)
    }
}

func TestDistinctCiphertexts(t *testing.T) {
    plain := []byte("same plaintext")
    pass := []byte("same pass")
    ct1, _ := Encrypt(plain, pass)
    ct2, _ := Encrypt(plain, pass)
    if bytes.Equal(ct1, ct2) {
        t.Fatal("two Encrypt calls produced identical ciphertext (missing randomization)")
    }
}

func TestWrongPassphrase(t *testing.T) {
    ct, _ := Encrypt([]byte("secret"), []byte("correct"))
    _, err := Decrypt(ct, []byte("wrong"))
    if !errors.Is(err, ErrBadPassphrase) {
        t.Fatalf("wrong passphrase: got %v, want ErrBadPassphrase", err)
    }
}

func TestTamperedCiphertext(t *testing.T) {
    ct, _ := Encrypt([]byte("secret"), []byte("pass"))
    // Flip the last byte of the GCM ciphertext+tag.
    tampered := append([]byte{}, ct...)
    tampered[len(tampered)-1] ^= 0xff
    _, err := Decrypt(tampered, []byte("pass"))
    if !errors.Is(err, ErrBadPassphrase) {
        t.Fatalf("tampered file: got %v, want ErrBadPassphrase", err)
    }
}

func TestTruncated(t *testing.T) {
    ct, _ := Encrypt([]byte("secret"), []byte("pass"))
    // Keep magic but truncate before end.
    short := ct[:overhead-1]
    _, err := Decrypt(short, []byte("pass"))
    if err == nil {
        t.Fatal("truncated file: expected error, got nil")
    }
}

func TestPlaintextPassthrough(t *testing.T) {
    plain := []byte("plaintext file, no magic prefix")
    if IsEncrypted(plain) {
        t.Fatal("IsEncrypted should be false for plaintext")
    }
    // Decrypt passes it through unchanged.
    got, err := Decrypt(plain, []byte("any passphrase"))
    if err != nil {
        t.Fatalf("Decrypt plaintext: %v", err)
    }
    if !bytes.Equal(got, plain) {
        t.Fatalf("plaintext passthrough corrupted: got %q", got)
    }
}
