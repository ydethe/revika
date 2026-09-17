package store

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestMemoryRoundTripAndLifecycle(t *testing.T) {
	ctx := context.Background()
	storage := NewMemory()
	if err := storage.Put(ctx, "object-1", stringsReader("opaque bytes")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, "object-1", stringsReader("duplicate")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate Put error = %v, want ErrAlreadyExists", err)
	}
	reader, err := storage.Get(ctx, "object-1")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "opaque bytes" {
		t.Fatalf("content = %q, want opaque bytes", data)
	}
	if err := storage.Delete(ctx, "object-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Get(ctx, "object-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Get error = %v, want ErrNotFound", err)
	}
}

func stringsReader(value string) io.Reader { return &stringReader{value: value} }

type stringReader struct {
	value string
	read  bool
}

func (r *stringReader) Read(data []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	return copy(data, r.value), nil
}
