package cap

import (
	"testing"
	"time"

	"github.com/revika/revika/internal/crypto"
)

func TestCapabilitySignsAndAuthorizesScope(t *testing.T) {
	signer, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	capability := New("item-1", Read|Write, []byte("recipient"), []byte("encrypted-key"), time.Now().Add(time.Hour))
	if err := capability.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if err := capability.Authorize("item-1", Write, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := capability.Authorize("item-2", Read, time.Now()); err != ErrUnauthorized {
		t.Fatalf("wrong scope error = %v, want ErrUnauthorized", err)
	}
}

func TestCapabilityRejectsTamperingAndExpiry(t *testing.T) {
	signer, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	capability := New("item-1", Read, nil, nil, time.Now().Add(time.Hour))
	if err := capability.Sign(signer); err != nil {
		t.Fatal(err)
	}
	capability.Scope = "item-2"
	if err := capability.Verify(time.Now()); err == nil {
		t.Fatal("tampered capability verified")
	}
	expired := New("item-1", Read, nil, nil, time.Now().Add(-time.Minute))
	if err := expired.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if err := expired.Verify(time.Now()); err != ErrExpired {
		t.Fatalf("expired capability error = %v, want ErrExpired", err)
	}
}
