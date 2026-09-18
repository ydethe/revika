package rootstore

import (
	"context"
	"errors"
	"testing"

	"github.com/revika/revika/internal/db"
)

func TestSQLiteRejectsRollbackAndPersists(t *testing.T) {
	signer := newSigner(t)
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	insertIdentity(t, database, "identity-1", signer.Public())

	store := NewSQLite(database.DB, "identity-1", signer.Public())
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

	reopened := NewSQLite(database.DB, "identity-1", signer.Public())
	reloaded, ok, err := reopened.Load(context.Background())
	if err != nil || !ok {
		t.Fatalf("reopened Load = (%v, %t, %v), want stored root", reloaded, ok, err)
	}
	if reloaded.Sequence != 2 || string(reloaded.Root) != "root-2" {
		t.Fatalf("reopened root = %#v, want sequence 2/root-2", reloaded)
	}
}

func TestSQLiteLoadReportsAbsence(t *testing.T) {
	signer := newSigner(t)
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := NewSQLite(database.DB, "identity-1", signer.Public())
	_, ok, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("Load reported presence on an empty database")
	}
}

func insertIdentity(t *testing.T, database *db.DB, id string, public []byte) {
	t.Helper()
	if _, err := database.Exec(
		`INSERT INTO identities(id, kind, public_key, private_key, algorithm, created_at_ns) VALUES (?, 'signing', ?, ?, 'ed25519', 0)`,
		id, public, []byte("private-key-placeholder"),
	); err != nil {
		t.Fatal(err)
	}
}
