// Command revika-ipfs-adapter runs an out-of-process revika storage adapter backed by a
// Kubo (go-ipfs) node. It speaks the rvk-plugin-v1 frame protocol on TCP (Hop A, the
// normative revika adapter contract in docs/Architecture.md §4.5.1) and translates each
// store operation into Kubo MFS HTTP RPC calls (Hop B). Only opaque ciphertext and hashed
// identifiers ever reach it; it never sees plaintext or keys.
//
// Configuration is via environment variables:
//
//	REVIKA_ADAPTER_LISTEN  TCP address to listen on (default ":9090").
//	REVIKA_IPFS_API        Kubo HTTP RPC base URL (default "http://kubo:5001").
//	REVIKA_ADAPTER_SECRET  Shared secret for the handshake (required).
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/revika/revika/internal/ipfsstore"
	"github.com/revika/revika/internal/netframe"
)

func main() {
	listenAddr := envOr("REVIKA_ADAPTER_LISTEN", ":9090")
	ipfsAPI := envOr("REVIKA_IPFS_API", "http://kubo:5001")
	secret := []byte(os.Getenv("REVIKA_ADAPTER_SECRET"))
	if len(secret) == 0 {
		log.Fatal("revika-ipfs-adapter: REVIKA_ADAPTER_SECRET must be set")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	backend := ipfsstore.New(ipfsAPI, nil)
	defer backend.Close()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("revika-ipfs-adapter: listen %s: %v", listenAddr, err)
	}
	log.Printf("revika-ipfs-adapter: listening on %s, ipfs %s", listener.Addr(), ipfsAPI)

	if err := netframe.Serve(ctx, listener, backend, secret); err != nil && ctx.Err() == nil {
		log.Fatalf("revika-ipfs-adapter: serve: %v", err)
	}
	log.Print("revika-ipfs-adapter: shutdown")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
