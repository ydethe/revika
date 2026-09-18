// Command revika-client-smoke is an E2E smoke test for the revika-client CLI. It waits for
// the adapter to accept connections, then drives the real revika-client binary through a
// full namespace round trip: cp (upload) -> ls -> cp (download, byte-for-byte check) -> rm ->
// ls (must no longer list the item). It exits 0 on success, non-zero on any mismatch. It is
// the "client-ns" service of deploy/ipfs, alongside the store-level revika-smoke check.
//
// Configuration is via environment variables:
//
//	REVIKA_ADAPTER_ADDR    Adapter TCP address (default "adapter:9090").
//	REVIKA_ADAPTER_SECRET  Shared secret for the handshake (required).
//	REVIKA_CLIENT_BIN      Path to the revika-client binary (default "/usr/local/bin/revika-client").
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/revika/revika/internal/netframe"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("revika-client-smoke: FAIL: %v", err)
	}
	log.Print("revika-client-smoke: PASS")
}

func run() error {
	addr := envOr("REVIKA_ADAPTER_ADDR", "adapter:9090")
	secret := os.Getenv("REVIKA_ADAPTER_SECRET")
	if secret == "" {
		return errors.New("REVIKA_ADAPTER_SECRET must be set")
	}
	clientBin := envOr("REVIKA_CLIENT_BIN", "/usr/local/bin/revika-client")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := waitForAdapter(ctx, addr, secret); err != nil {
		return err
	}
	log.Printf("adapter at %s is accepting connections", addr)

	work, err := os.MkdirTemp("", "revika-client-smoke-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	dbPath := filepath.Join(work, "client.db")
	localSrc := filepath.Join(work, "smoke.txt")
	payload := []byte("revika-client-smoke namespace round-trip payload\n")
	if err := os.WriteFile(localSrc, payload, 0o600); err != nil {
		return err
	}

	cli := func(args ...string) (string, error) {
		fullArgs := append([]string{"-addr", addr, "-secret", secret, "-db", dbPath}, args...)
		cmd := exec.CommandContext(ctx, clientBin, fullArgs...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return out.String(), err
	}

	if out, err := cli("pwd"); err != nil {
		return fmt.Errorf("pwd: %w (output: %s)", err, out)
	} else if out != "rvk:/\n" {
		return fmt.Errorf("pwd output = %q, want %q", out, "rvk:/\n")
	}
	log.Print("pwd reports rvk:/")

	if out, err := cli("cp", localSrc, "rvk:smoke.txt"); err != nil {
		return fmt.Errorf("cp upload: %w (output: %s)", err, out)
	}
	log.Print("uploaded smoke.txt")

	if out, err := cli("ls"); err != nil {
		return fmt.Errorf("ls: %w (output: %s)", err, out)
	} else if !bytes.Contains([]byte(out), []byte("smoke.txt")) {
		return fmt.Errorf("ls output %q does not list smoke.txt", out)
	}
	log.Print("ls lists smoke.txt")

	downloaded := filepath.Join(work, "downloaded.txt")
	if out, err := cli("cp", "rvk:smoke.txt", downloaded); err != nil {
		return fmt.Errorf("cp download: %w (output: %s)", err, out)
	}
	got, err := os.ReadFile(downloaded)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("downloaded content = %q, want %q", got, payload)
	}
	log.Print("downloaded content matches byte-for-byte")

	if out, err := cli("rm", "rvk:smoke.txt"); err != nil {
		return fmt.Errorf("rm: %w (output: %s)", err, out)
	}
	log.Print("removed smoke.txt")

	if out, err := cli("ls"); err != nil {
		return fmt.Errorf("ls after rm: %w (output: %s)", err, out)
	} else if bytes.Contains([]byte(out), []byte("smoke.txt")) {
		return fmt.Errorf("ls output %q still lists smoke.txt after rm", out)
	}
	log.Print("ls no longer lists smoke.txt after rm")

	return nil
}

// waitForAdapter retries a handshake-only dial until the adapter accepts connections, so
// this smoke test can start alongside the adapter without a race; the real work goes
// through the revika-client subprocess, which does not retry.
func waitForAdapter(ctx context.Context, addr, secret string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		client, err := netframe.Dial(ctx, addr, []byte(secret))
		if err == nil {
			return client.Close()
		}
		log.Printf("adapter not ready (%v), retrying", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
