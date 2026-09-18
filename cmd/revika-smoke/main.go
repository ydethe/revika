// Command revika-smoke is a demo client for the IPFS adapter stack. It dials the adapter
// over the rvk-plugin-v1 frame protocol (retrying until the adapter is up), then exercises
// the full store.Store round-trip against it: Put, Get (with a byte-for-byte check), Has,
// Delete, and a final Has that must report absence. It logs each step and exits 0 on
// success, non-zero on any failure. It is the "client" service of deploy/ipfs.
//
// Configuration is via environment variables:
//
//	REVIKA_ADAPTER_ADDR    Adapter TCP address (default "adapter:9090").
//	REVIKA_ADAPTER_SECRET  Shared secret for the handshake (required).
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"time"

	"github.com/revika/revika/internal/netframe"
	"github.com/revika/revika/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("revika-smoke: FAIL: %v", err)
	}
	log.Print("revika-smoke: PASS")
}

func run() error {
	addr := envOr("REVIKA_ADAPTER_ADDR", "adapter:9090")
	secret := []byte(os.Getenv("REVIKA_ADAPTER_SECRET"))
	if len(secret) == 0 {
		return errors.New("REVIKA_ADAPTER_SECRET must be set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := dialWithRetry(ctx, addr, secret)
	if err != nil {
		return err
	}
	defer client.Close()
	log.Printf("connected to adapter at %s", addr)

	const id = store.ObjectID("smoke-test-object")
	payload := []byte("revika smoke-test ciphertext payload")

	if err := client.Put(ctx, id, bytes.NewReader(payload)); err != nil {
		return err
	}
	log.Printf("put %d bytes as %q", len(payload), id)

	reader, err := client.Get(ctx, id)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("get returned different bytes than were put")
	}
	log.Printf("get returned %d bytes, matches", len(got))

	present, err := client.Has(ctx, id)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("has reported absence after put")
	}
	log.Print("has reports present")

	if err := client.Delete(ctx, id); err != nil {
		return err
	}
	log.Print("deleted object")

	present, err = client.Has(ctx, id)
	if err != nil {
		return err
	}
	if present {
		return errors.New("has reported presence after delete")
	}
	log.Print("has reports absent after delete")
	return nil
}

// dialWithRetry retries Dial until the adapter accepts a connection or ctx expires, so the
// client can start alongside the adapter without a race.
func dialWithRetry(ctx context.Context, addr string, secret []byte) (*netframe.Client, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		client, err := netframe.Dial(ctx, addr, secret)
		if err == nil {
			return client, nil
		}
		log.Printf("adapter not ready (%v), retrying", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
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
