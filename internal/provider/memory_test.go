package provider

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestMemoryProviderRoundTripAndStableRename(t *testing.T) {
	ctx := context.Background()
	provider := NewMemory()
	created, err := provider.CreateItem(ctx, RootID, CreateRequest{Name: "note.txt", Contents: strings.NewReader("hello")})
	if err != nil {
		t.Fatal(err)
	}
	fetched := bytes.NewBuffer(nil)
	version, err := provider.FetchContents(ctx, created.ID, fetched)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.String() != "hello" || string(version.Content) != string(created.Version.Content) {
		t.Fatalf("fetched content/version = %q/%x", fetched.String(), version.Content)
	}
	renamed, err := provider.Rename(ctx, created.ID, RootID, "renamed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != created.ID {
		t.Fatal("rename changed the stable item ID")
	}
	if _, err := provider.Lookup(ctx, RootID, "note.txt"); err != ErrNotFound {
		t.Fatalf("old name lookup error = %v, want ErrNotFound", err)
	}
	if _, err := provider.Lookup(ctx, RootID, "renamed.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryProviderEnumeratesChanges(t *testing.T) {
	ctx := context.Background()
	provider := NewMemory()
	initial, err := provider.CurrentAnchor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created, err := provider.CreateItem(ctx, RootID, CreateRequest{Name: "file", Contents: strings.NewReader("one")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ModifyItem(ctx, created.ID, ModifyRequest{Contents: strings.NewReader("two")}); err != nil {
		t.Fatal(err)
	}
	changes, err := provider.EnumerateChanges(ctx, initial)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 2 {
		t.Fatalf("change count = %d, want 2", len(changes.Changes))
	}
	if changes.Anchor.Sequence <= initial.Sequence {
		t.Fatal("change anchor did not advance")
	}
	var output bytes.Buffer
	if _, err := io.Copy(&output, strings.NewReader("ok")); err != nil {
		t.Fatal(err)
	}
}
