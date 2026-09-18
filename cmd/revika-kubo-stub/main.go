// Command revika-kubo-stub is a tiny, hermetic stand-in for a Kubo (go-ipfs) node's
// mutable-files (MFS) HTTP RPC surface. It implements just the four endpoints the revika
// IPFS adapter uses — /api/v0/files/{write,read,stat,rm} — backed by an in-memory map keyed
// by MFS path. It exists so CI can drive the *real* revika-ipfs-adapter and revika-smoke
// binaries end to end without pulling the heavy Kubo image or ever touching the public IPFS
// network. It mirrors the fakeKubo used by internal/ipfsstore's unit tests, promoted to a
// standalone process for the multi-process E2E in scripts/e2e.sh.
//
// It is a TEST/CI fixture, not a real storage backend: state is in-memory and lost on exit.
//
// Configuration is via environment variables:
//
//	REVIKA_KUBO_STUB_LISTEN  TCP address to listen on (default "127.0.0.1:5001").
package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	listenAddr := envOr("REVIKA_KUBO_STUB_LISTEN", "127.0.0.1:5001")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("revika-kubo-stub: listen %s: %v", listenAddr, err)
	}

	server := &http.Server{Handler: newStub()}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	log.Printf("revika-kubo-stub: serving MFS RPC on %s", listener.Addr())
	if err := server.Serve(listener); err != nil && ctx.Err() == nil {
		log.Fatalf("revika-kubo-stub: serve: %v", err)
	}
	log.Print("revika-kubo-stub: shutdown")
}

// stub is an in-memory MFS namespace addressed by the request's "arg" (the MFS path).
type stub struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newStub() *stub { return &stub{files: make(map[string][]byte)} }

// notExist replies the way Kubo does for a missing MFS path: HTTP 500 with a
// "file does not exist" message, which ipfsstore classifies as store.ErrNotFound.
func (s *stub) notExist(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	io.WriteString(w, `{"Message":"file does not exist","Code":0,"Type":"error"}`)
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Kubo's RPC API is POST-only.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Query().Get("arg")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/api/v0/files/write":
		file, _, err := r.FormFile("data")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		content, err := io.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.files[path] = content
	case "/api/v0/files/read":
		content, ok := s.files[path]
		if !ok {
			s.notExist(w)
			return
		}
		w.Write(content)
	case "/api/v0/files/stat":
		if _, ok := s.files[path]; !ok {
			s.notExist(w)
			return
		}
		io.WriteString(w, `{"Type":"file"}`)
	case "/api/v0/files/rm":
		delete(s.files, path)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
