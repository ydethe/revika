package store

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDiskRoundTripPersistsAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := NewDisk(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Put(context.Background(), "object-1", strings.NewReader("persisted")); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := NewDisk(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	reader, err := second.Get(context.Background(), "object-1")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "persisted" {
		t.Fatalf("content = %q, want persisted", content)
	}
	if err := second.Delete(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Delete error = %v, want ErrNotFound", err)
	}
}
