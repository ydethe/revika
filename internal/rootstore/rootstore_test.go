package rootstore

import (
	"context"
	"errors"
	"testing"

	"github.com/revika/revika/internal/crypto"
)

func TestMemoryRejectsRollbackAndInvalidOwner(t *testing.T) {
	signer := newSigner(t)
	store := NewMemory(signer.Public())
	first, err := NewPointer(signer, 1, 100, []byte("root-1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), first); !errors.Is(err, ErrRollback) {
		t.Fatalf("same sequence error = %v, want ErrRollback", err)
	}
	second, err := NewPointer(signer, 2, 200, []byte("root-2"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := store.Load(context.Background())
	if err != nil || !ok {
		t.Fatalf("Load = (%v, %t, %v), want stored root", loaded, ok, err)
	}
	if loaded.Sequence != 2 || string(loaded.Root) != "root-2" {
		t.Fatalf("loaded root = %#v, want sequence 2/root-2", loaded)
	}
}

func TestFileRoundTripAndTamperRejection(t *testing.T) {
	signer := newSigner(t)
	path := t.TempDir() + "/root.json"
	store := NewFile(path, signer.Public())
	pointer, err := NewPointer(signer, 1, 100, []byte("root"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), pointer); err != nil {
		t.Fatal(err)
	}
	reopened := NewFile(path, signer.Public())
	loaded, ok, err := reopened.Load(context.Background())
	if err != nil || !ok {
		t.Fatalf("Load = (%v, %t, %v), want stored root", loaded, ok, err)
	}
	if loaded.Sequence != pointer.Sequence || string(loaded.Root) != string(pointer.Root) {
		t.Fatalf("loaded root = %#v, want %#v", loaded, pointer)
	}
	data := append([]byte(nil), pointer.Signature...)
	data[0] ^= 1
	pointer.Signature = data
	if err := reopened.Save(context.Background(), pointer); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("tampered Save error = %v, want invalid root", err)
	}
}

func newSigner(t *testing.T) *crypto.Ed25519Signer {
	t.Helper()
	signer, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
