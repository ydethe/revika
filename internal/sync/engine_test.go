package sync

import (
	"context"
	"strings"
	"testing"

	"github.com/revika/revika/internal/provider"
)

func TestEnginePullsRemoteChangesAndPushesLocalMutations(t *testing.T) {
	ctx := context.Background()
	remote := provider.NewMemory()
	local := &testSurface{pending: []Mutation{{Type: MutationCreate, Parent: provider.RootID, Name: "local.txt", Contents: []byte("local")}}}
	anchors := &MemoryAnchorStore{}
	engine := Engine{Provider: remote, Surface: local, Anchors: anchors}
	if err := engine.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Lookup(ctx, provider.RootID, "local.txt"); err != nil {
		t.Fatal(err)
	}
	if local.acknowledged != 1 {
		t.Fatalf("acknowledged mutations = %d, want 1", local.acknowledged)
	}
	if local.applied != 0 {
		t.Fatalf("remote changes applied = %d, want 0", local.applied)
	}

	if _, err := remote.CreateItem(ctx, provider.RootID, provider.CreateRequest{Name: "remote.txt", Contents: strings.NewReader("remote")}); err != nil {
		t.Fatal(err)
	}
	local.pending = nil
	if err := engine.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if local.applied != 1 {
		t.Fatalf("remote changes applied = %d, want 1", local.applied)
	}
}

type testSurface struct {
	pending      []Mutation
	applied      int
	acknowledged int
}

func (surface *testSurface) ApplyRemote(_ context.Context, changes []provider.Change) error {
	surface.applied += len(changes)
	return nil
}

func (surface *testSurface) Pending(_ context.Context) ([]Mutation, error) {
	return append([]Mutation(nil), surface.pending...), nil
}

func (surface *testSurface) Acknowledge(_ context.Context, mutations []Mutation) error {
	surface.acknowledged += len(mutations)
	surface.pending = nil
	return nil
}

func (surface *testSurface) Conflict(_ context.Context, _ Mutation, _ uint64) error { return nil }
