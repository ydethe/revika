package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/revika/revika/internal/daemon"
)

func main() {
	ledgerPath := flag.String("ledger", ".revika/daemon-ledger.json", "Ledger file path")
	ipfsAPI := flag.String("ipfs-api", "127.0.0.1:5001", "Kubo RPC API address")
	ipcAddr := flag.String("ipc", "/tmp/revika-daemon.sock", "IPC socket address")
	flag.Parse()

	// Create and start the daemon service
	svc, err := daemon.NewService(*ledgerPath, *ipfsAPI, *ipcAddr)
	if err != nil {
		log.Fatalf("failed to create daemon service: %v", err)
	}

	if err := svc.Start(); err != nil {
		log.Fatalf("failed to start daemon service: %v", err)
	}

	log.Printf("User Daemon started (peer ID: %s)", svc.GetPeerID())

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Shutting down daemon...")
	if err := svc.Stop(); err != nil {
		log.Printf("error during shutdown: %v", err)
		os.Exit(1)
	}

	log.Printf("Daemon stopped")
}
