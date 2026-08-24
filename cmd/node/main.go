package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/revika/revika/internal/node"
)

func main() {
	storeDir := flag.String("store", ".revika/node-store", "Store directory for shards")
	ledgerPath := flag.String("ledger", ".revika/node-ledger.json", "Ledger file path")
	ipfsAPI := flag.String("ipfs-api", "127.0.0.1:5001", "Kubo RPC API address")
	flag.Parse()

	// Create and start the node server
	srv, err := node.NewServer(*storeDir, *ledgerPath, *ipfsAPI)
	if err != nil {
		log.Fatalf("failed to create node server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("failed to start node server: %v", err)
	}

	log.Printf("Node server started (peer ID: %s)", srv.GetPeerID())

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Shutting down node server...")
	if err := srv.Stop(); err != nil {
		log.Printf("error during shutdown: %v", err)
		os.Exit(1)
	}

	log.Printf("Node server stopped")
}
