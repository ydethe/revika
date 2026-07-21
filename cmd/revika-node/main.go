// Command revika-node is the headless Node server: it contributes storage to
// the revika network by serving encrypted, erasure-coded shards over libp2p. A
// node is a dumb, untrusted blob store — it never sees plaintext, keys, or
// manifests, only opaque shards addressed by content hash.
//
// Usage:
//
//	revika-node [flags]
//
// It loads (or creates) a stable libp2p identity, opens an on-disk shard store,
// starts a libp2p host serving /revika/shard and /revika/probe, prints its
// dialable addresses, and runs until interrupted (SIGINT/SIGTERM).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"revika/internal/ledger"
	"revika/internal/net"
	"revika/internal/store"
)

// reprovideInterval is how often a node re-announces the shards it holds to the
// DHT. Provider records expire (libp2p's default TTL is ~24h), so they must be
// refreshed well within that window or the shards become undiscoverable.
const reprovideInterval = 12 * time.Hour

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "revika-node:", err)
		os.Exit(1)
	}
}

// multiFlag collects a repeatable string flag (e.g. -listen a -listen b).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func run() error {
	var (
		dataDir     = flag.String("data", ".revika", "root directory for node state (shards, identity)")
		verbose     = flag.Bool("v", false, "verbose (debug) logging")
		mdnsOn      = flag.Bool("mdns", true, "enable mDNS LAN peer discovery")
		dhtOn       = flag.Bool("dht", true, "join the Kademlia DHT (WAN discovery + provider records)")
		advertiseOn = flag.Bool("advertise", true, "advertise this node as a storage provider on the DHT")
		quota       = flag.Int64("quota", 0, "per-owner storage quota in bytes (0 = unlimited)")
		leaseTTL    = flag.Duration("lease-ttl", 720*time.Hour, "lease lifetime granted on PUT (advisory unless -gc-expired-leases)")
		gcInterval  = flag.Duration("gc-interval", time.Hour, "how often the garbage collector runs")
		gcExpired   = flag.Bool("gc-expired-leases", false, "also collect shards whose leases have all expired (off: own-until-delete)")
		listen      multiFlag
		bootstrap   multiFlag
	)
	flag.Var(&listen, "listen", "multiaddr to listen on (repeatable; default all interfaces, random TCP+QUIC ports)")
	flag.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr with /p2p/<id> (repeatable)")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// The process-lifetime context: cancelled on SIGINT/SIGTERM, it bounds the
	// DHT and its background loops so they stop cleanly on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shardsDir := filepath.Join(*dataDir, "shards")
	blobs, err := store.NewDiskStore(shardsDir)
	if err != nil {
		return fmt.Errorf("open shard store: %w", err)
	}

	// The ledger tracks who owns each shard and enforces quotas; it is the source
	// of truth for ownership, while blobs on disk are the source of truth for
	// bytes. Reconcile the two on startup before serving.
	ledgerPath := filepath.Join(*dataDir, "ledger", "ledger.db")
	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0o700); err != nil {
		return fmt.Errorf("create ledger dir: %w", err)
	}
	led, err := ledger.Open(ledgerPath, ledger.Options{QuotaBytes: *quota, LeaseTTL: *leaseTTL})
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer led.Close()
	if rep, err := led.Reconcile(ctx, blobs); err != nil {
		return fmt.Errorf("reconcile ledger: %w", err)
	} else if rep.OrphanBlobs > 0 || rep.DroppedRecords > 0 {
		log.Info("ledger reconciled", "orphan_blobs", rep.OrphanBlobs, "dropped_records", rep.DroppedRecords)
	}

	h, err := net.NewHost(net.HostConfig{
		ListenAddrs:  listen,
		IdentityPath: filepath.Join(*dataDir, "keys", "node.key"),
		EnableMDNS:   *mdnsOn,
	})
	if err != nil {
		return err
	}
	defer h.Close()

	srv := net.NewServer(blobs, log)
	srv.SetLedger(led)

	// Join the DHT (server mode: a node stores routing state + provider records
	// for others). Wiring the Discovery in as the Server's announcer means every
	// shard the node accepts is advertised, and a background loop reprovides the
	// shards it already holds so they stay discoverable across restarts.
	var disc *net.Discovery
	if *dhtOn {
		disc, err = net.NewDiscovery(ctx, h, net.DiscoveryConfig{
			Mode:      net.DHTModeServer,
			Bootstrap: bootstrap,
			Log:       log,
		})
		if err != nil {
			return fmt.Errorf("start dht: %w", err)
		}
		defer disc.Close()
		srv.SetAnnouncer(disc)
		if *advertiseOn {
			disc.AdvertiseLoop(ctx)
		}
		go reprovideLoop(ctx, disc, blobs, log)
	}

	srv.Register(h)

	// Garbage collector: reclaim shards no owner holds any longer (and, if
	// enabled, expired leases), keeping disk and ledger aligned.
	go gcLoop(ctx, blobs, led, log, *gcInterval, *gcExpired)

	log.Info("revika-node started",
		"peer", h.ID().String(),
		"shards", shardsDir,
		"mdns", *mdnsOn,
		"dht", *dhtOn,
		"bootstrap", len(bootstrap),
	)
	fmt.Println("Peer ID:", h.ID())
	fmt.Println("Listening on:")
	for _, a := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", a, h.ID())
	}
	if *dhtOn {
		fmt.Printf("DHT: server mode, %d bootstrap peer(s), advertising=%v\n", len(bootstrap), *advertiseOn)
	}

	// Block until interrupted, then shut down cleanly.
	<-ctx.Done()
	log.Info("shutting down")
	return nil
}

// reprovideLoop announces every shard the node holds to the DHT on startup and
// then on a fixed cadence, refreshing provider records before they expire. It
// runs until ctx is cancelled. If the store cannot enumerate its shards (does
// not implement store.Lister), reproviding is skipped with a log note — newly
// stored shards are still announced on Put by the Server's announcer.
func reprovideLoop(ctx context.Context, disc *net.Discovery, blobs store.Store, log *slog.Logger) {
	lister, ok := blobs.(store.Lister)
	if !ok {
		log.Warn("dht: shard store is not enumerable; skipping periodic reprovide")
		return
	}
	ticker := time.NewTicker(reprovideInterval)
	defer ticker.Stop()
	for {
		ids, err := lister.List(ctx)
		if err != nil {
			log.Warn("dht: list shards for reprovide", "err", err)
		} else if len(ids) > 0 {
			log.Debug("dht: reproviding shards", "count", len(ids))
			disc.ProvideAll(ctx, ids)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// gcLoop runs the garbage collector on a fixed cadence until ctx is cancelled.
// Each cycle reclaims shards that are no longer owned (and, if expireLeases is
// set, whose leases have all lapsed), then reconciles the ledger with disk.
//
// A grace window guards against races: a shard is only collected once it has
// been collectible for two consecutive cycles, so a shard PUT or renewed moments
// before a sweep is never swept. The atomic CollectRecord drop plus the fact
// that a racing re-PUT re-creates the (content-addressed) blob make collection
// non-destructive even at the edges.
func gcLoop(ctx context.Context, blobs store.Store, led *ledger.Ledger, log *slog.Logger, interval time.Duration, expireLeases bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var prev map[store.ShardID]bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prev = runGC(ctx, blobs, led, log, expireLeases, prev)
		}
	}
}

// runGC performs one GC cycle and returns the set of shards seen collectible
// this cycle (the next cycle's grace baseline).
func runGC(ctx context.Context, blobs store.Store, led *ledger.Ledger, log *slog.Logger, expireLeases bool, prev map[store.ShardID]bool) map[store.ShardID]bool {
	ids, err := led.Collectible(time.Now(), expireLeases)
	if err != nil {
		log.Warn("gc: list collectible", "err", err)
		return prev
	}
	curr := make(map[store.ShardID]bool, len(ids))
	for _, id := range ids {
		curr[id] = true
	}
	var freed int
	for _, id := range ids {
		if ctx.Err() != nil {
			return curr
		}
		if !prev[id] {
			continue // grace: must be collectible two cycles running
		}
		// Atomically drop the record only if still unowned, then delete the blob.
		dropped, err := led.CollectRecord(id, time.Now(), expireLeases)
		if err != nil {
			log.Warn("gc: collect record", "id", id, "err", err)
			continue
		}
		if !dropped {
			continue // re-claimed since the snapshot
		}
		if err := blobs.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Warn("gc: delete blob", "id", id, "err", err)
			continue
		}
		freed++
	}
	if freed > 0 {
		log.Info("gc: reclaimed shards", "count", freed)
	}
	// Realign disk and ledger: drop records whose blob vanished, recompute quota.
	if rep, err := led.Reconcile(ctx, blobs); err != nil {
		log.Warn("gc: reconcile", "err", err)
	} else if rep.DroppedRecords > 0 {
		log.Info("gc: reconciled", "dropped_records", rep.DroppedRecords, "orphan_blobs", rep.OrphanBlobs)
	}
	return curr
}
