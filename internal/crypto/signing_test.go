package crypto

import (
	"testing"
)

func TestEd25519SigningAndVerification(t *testing.T) {
	signer, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("signed root")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(signer.Public(), message, signature); err != nil {
		t.Fatal(err)
	}
	message[0] ^= 1
	if err := VerifyEd25519(signer.Public(), message, signature); err != ErrInvalidSignature {
		t.Fatalf("tampered message error = %v, want ErrInvalidSignature", err)
	}
}

func TestNewEd25519SignerCopiesPrivateKey(t *testing.T) {
	signer, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	private := append([]byte(nil), signer.private...)
	copySigner, err := NewEd25519Signer(private)
	if err != nil {
		t.Fatal(err)
	}
	private[0] ^= 1
	if string(copySigner.Public()) != string(signer.Public()) {
		t.Fatal("signer retained an aliased private key")
	}
}
