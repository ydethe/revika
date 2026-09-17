package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

const SignatureVersion uint8 = 1

var ErrInvalidSignature = errors.New("crypto: invalid signature")

type Signer interface {
	Public() []byte
	Sign(message []byte) ([]byte, error)
}

type Ed25519Signer struct {
	private ed25519.PrivateKey
}

func GenerateEd25519() (*Ed25519Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{private: private}, nil
}

func NewEd25519Signer(private []byte) (*Ed25519Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: invalid Ed25519 private key length")
	}
	return &Ed25519Signer{private: ed25519.PrivateKey(append([]byte(nil), private...))}, nil
}

func (s *Ed25519Signer) Public() []byte {
	public := s.private.Public().(ed25519.PublicKey)
	return append([]byte(nil), public...)
}

func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.private, message), nil
}

func VerifyEd25519(public, message, signature []byte) error {
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return ErrInvalidSignature
	}
	return nil
}
