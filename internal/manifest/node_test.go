package manifest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/revika/revika/internal/store"
)

func TestNodeAddressAndRoundTrip(t *testing.T) {
	objects := store.NewMemory()
	node := NewDirectory([]byte("metadata"), map[string]Reference{
		"b.txt": {ID: "file-b", Kind: KindFile, Size: 2},
		"a.txt": {ID: "file-a", Kind: KindFile, Size: 1},
	})
	address, err := Save(context.Background(), objects, node)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(context.Background(), objects, address)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Kind != KindDirectory || loaded.Children["a.txt"].ID != "file-a" {
		t.Fatalf("loaded node = %#v", loaded)
	}
	secondAddress, err := Save(context.Background(), objects, node)
	if err != nil || secondAddress != address {
		t.Fatalf("second Save = %q, %v; want %q", secondAddress, err, address)
	}
}

func TestLoadRejectsCorruptedObject(t *testing.T) {
	objects := store.NewMemory()
	if err := objects.Put(context.Background(), store.ObjectID("address"), strings.NewReader("corrupted")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), objects, "address"); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("Load error = %v, want ErrInvalidNode", err)
	}
}
