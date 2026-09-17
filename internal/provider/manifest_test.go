package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/revika/revika/internal/crypto"
	"github.com/revika/revika/internal/rootstore"
	"github.com/revika/revika/internal/store"
)

func TestManifestProviderPersistsAndReopens(t *testing.T) {
	ctx := context.Background()
	signer, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	objects := store.NewMemory()
	roots := rootstore.NewMemory(signer.Public())
	provider, err := New(ctx, objects, signer, roots)
	if err != nil {
		t.Fatal(err)
	}
	created, err := provider.CreateItem(ctx, RootID, CreateRequest{Name: "persisted.txt", Contents: strings.NewReader("persisted content")})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := New(ctx, objects, signer, roots)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Lookup(ctx, RootID, "persisted.txt")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != created.ID {
		t.Fatalf("reopened ID = %q, want %q", loaded.ID, created.ID)
	}
	changes, err := reopened.EnumerateChanges(ctx, SyncAnchor{Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 1 {
		t.Fatalf("reopened change count = %d, want 1", len(changes.Changes))
	}
}
