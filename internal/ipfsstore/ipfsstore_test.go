package ipfsstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/revika/revika/internal/store"
)

// fakeKubo is a minimal stand-in for a Kubo node's MFS HTTP RPC surface, backed by an
// in-memory map keyed by the requested MFS path. It implements just enough of
// /api/v0/files/{write,read,stat,rm} for the store to exercise.
type fakeKubo struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newFakeKubo() *fakeKubo {
	return &fakeKubo{files: make(map[string][]byte)}
}

func (f *fakeKubo) notExist(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	io.WriteString(w, `{"Message":"file does not exist","Code":0,"Type":"error"}`)
}

func (f *fakeKubo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Query().Get("arg")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/v0/files/write":
		file, _, err := r.FormFile("data")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		content, _ := io.ReadAll(file)
		f.files[path] = content
	case "/api/v0/files/read":
		content, ok := f.files[path]
		if !ok {
			f.notExist(w)
			return
		}
		w.Write(content)
	case "/api/v0/files/stat":
		if _, ok := f.files[path]; !ok {
			f.notExist(w)
			return
		}
		io.WriteString(w, `{"Type":"file"}`)
	case "/api/v0/files/rm":
		delete(f.files, path)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestStore(t *testing.T) (*Store, *fakeKubo) {
	t.Helper()
	fake := newFakeKubo()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return New(server.URL, server.Client()), fake
}

func TestPutGetRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const id = store.ObjectID("object")
	payload := []byte("opaque ciphertext")

	if err := s.Put(ctx, id, bytes.NewReader(payload)); err != nil {
		t.Fatalf("put: %v", err)
	}
	reader, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestGetMissingIsNotFound(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.Get(context.Background(), store.ObjectID("missing"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPutDuplicateIsAlreadyExists(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const id = store.ObjectID("dup")
	if err := s.Put(ctx, id, bytes.NewReader([]byte("first"))); err != nil {
		t.Fatalf("first put: %v", err)
	}
	err := s.Put(ctx, id, bytes.NewReader([]byte("second")))
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestHas(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const id = store.ObjectID("probe")

	present, err := s.Has(ctx, id)
	if err != nil {
		t.Fatalf("has before put: %v", err)
	}
	if present {
		t.Fatal("expected absent before put")
	}
	if err := s.Put(ctx, id, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("put: %v", err)
	}
	present, err = s.Has(ctx, id)
	if err != nil {
		t.Fatalf("has after put: %v", err)
	}
	if !present {
		t.Fatal("expected present after put")
	}
}

func TestDeleteRemoves(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const id = store.ObjectID("removeme")
	if err := s.Put(ctx, id, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	present, err := s.Has(ctx, id)
	if err != nil {
		t.Fatalf("has: %v", err)
	}
	if present {
		t.Fatal("expected absent after delete")
	}
}

func TestDeleteMissingIsNotFound(t *testing.T) {
	s, _ := newTestStore(t)
	err := s.Delete(context.Background(), store.ObjectID("missing"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestObjectIDMapsToHashedPath(t *testing.T) {
	path := mfsPath(store.ObjectID("anything"))
	if !strings.HasPrefix(path, basePath+"/") {
		t.Fatalf("path %q not under %q", path, basePath)
	}
	if strings.Contains(path, "anything") {
		t.Fatalf("path %q leaks the raw id", path)
	}
}
