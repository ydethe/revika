package main

import (
	"bufio"
	"flag"
	"log"
	"os"

	"github.com/revika/revika/internal/cli"
)

func main() {
	ipcAddr := flag.String("ipc", "/tmp/revika-daemon.sock", "Daemon IPC socket address")
	flag.Parse()

	// Create and run the interactive CLI shell
	shell := cli.NewShell(*ipcAddr)
	defer shell.Close()

	// Set up stdin for reading commands
	reader := bufio.NewReader(os.Stdin)

	// Run the interactive shell
	if err := shell.RunWithReader(reader); err != nil {
		log.Fatal(err)
	}
}
