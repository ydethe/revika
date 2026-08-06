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
//
// When it participates in the DHT it also runs a repair loop: it probes the
// stripes it holds and regenerates missing shards onto fresh nodes while at least
// K survive, using only the non-confidential stripe descriptor and a User-signed
// repair grant recorded at store time (never the encryption key).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/erasure"
	"revika/internal/ledger"
	"revika/internal/net"
	"revika/internal/pipeline"
	"revika/internal/repair"
	"revika/internal/store"
	"revika/internal/stripe"
)

// reprovideInterval is how often a node re-announces the shards it holds to the
// DHT. Provider records expire (libp2p's default TTL is ~24h), so they must be
// refreshed well within that window or the shards become undiscoverable.
const reprovideInterval = 12 * time.Hour

// discoveryInterval is how often a node actively scans the DHT for other
// advertised storage nodes, and discoveryScanTimeout bounds one such scan.
// Without this a node at rest — holding no shards, so its repair loop makes no
// DHT queries — never emits a "discovered node" line even though
// bootstrap succeeded and the routing tables interconnect. The scan also warms
// each node's view of its peers rather than only learning them lazily on the
// first client or repair query.
const (
	discoveryInterval    = time.Minute
	discoveryScanTimeout = 30 * time.Second
)

// bootstrapDialTimeout bounds connecting to and querying a single bootstrap peer
// when a joining node learns the network's proof-of-work policy over
// /revika/params (see the PoW block in run()).
const bootstrapDialTimeout = 30 * time.Second

// version is the build version reported on /status and /metrics. Override at
// build time with -ldflags="-X main.version=v1.2.3".
var version = "dev"

// buildDate is the UTC timestamp the binary was built, reported on startup.
// Override at build time with -ldflags="-X main.buildDate=2026-08-05T12:00:00Z".
var buildDate = "unknown"

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
		verbose     = flag.Bool("v", false, "verbose (debug) logging; shorthand for -log-level debug")
		logFormat   = flag.String("log-format", "auto", "log encoding: auto (text on a terminal, JSON otherwise), text, or json. JSON is structured for Grafana Alloy/Loki (time, level, msg, event fields)")
		logLevel    = flag.String("log-level", "info", "minimum log level: debug, info, warn, or error")
		dhtOn       = flag.Bool("dht", true, "join the Kademlia DHT (WAN discovery + provider records)")
		advertiseOn = flag.Bool("advertise", true, "advertise this node as a storage provider on the DHT")
		quota       = flag.Int64("quota", 0, "per-owner storage quota in bytes (0 = unlimited)")
		leaseTTL    = flag.Duration("lease-ttl", 720*time.Hour, "lease lifetime granted on PUT (advisory unless -gc-expired-leases)")
		gcInterval  = flag.Duration("gc-interval", time.Hour, "how often the garbage collector runs")
		gcExpired   = flag.Bool("gc-expired-leases", false, "also collect shards whose leases have all expired (off: own-until-delete)")
		repairOn    = flag.Bool("repair", true, "run the repair loop: probe stripes this node holds and regenerate missing shards")
		repairEvery = flag.Duration("repair-interval", time.Hour, "how often the repair loop runs")
		rebalanceOn = flag.Bool("rebalance", true, "run the rebalance loop: offload cold shards to emptier nodes so storage load converges across the network (needs the DHT)")
		rebalEvery  = flag.Duration("rebalance-interval", time.Hour, "how often the rebalance loop runs")
		rebalThresh = flag.Float64("rebalance-threshold", 0.10, "minimum load-fraction gap (0-1) before offloading a shard: a dead-band that prevents thrashing")
		capacity    = flag.Int64("capacity", 0, "usable storage budget in bytes for load balancing (0 = use the shard filesystem's total capacity)")
		metricsAddr = flag.String("metrics", ":9096", "address for the HTTP metrics/status server (host:port; empty disables). Serves /healthz /readyz /status /metrics over plain HTTP — put TLS on a reverse proxy")
		blocklist   = flag.String("blocklist", "", "path to a static blocklist file (one peer ID, CIDR, or IP per line; '#' comments) refused by the connection gater")
		connLow     = flag.Int("conn-low", 0, "connection-manager low watermark (0 = built-in default)")
		connHigh    = flag.Int("conn-high", 0, "connection-manager high watermark, above which idle connections are trimmed (0 = built-in default; <0 disables)")
		connGrace   = flag.Duration("conn-grace", 0, "grace period protecting a new connection from trimming (0 = built-in default)")
		powDiff     = flag.Uint("pow-difficulty", 0, "require owner identities to be self-certifying: proof-of-work difficulty in leading zero bits admitted on PUT (0 = disabled). Clients must keygen with a matching -pow-puzzle and difficulty >= this")
		powPuzzle   = flag.String("pow-puzzle", "argon2id", "proof-of-work puzzle owner identities must satisfy: argon2id (memory-hard) or sha256 (fast). Must match what clients mint with")
		publicIP    = flag.String("public-ip", "", "externally reachable public IP (IPv4/IPv6) to advertise for a NAT'd node; each listen address gains a public variant (assumes the public port equals the bound port)")
		listen      multiFlag
		bootstrap   multiFlag
	)
	flag.Var(&listen, "listen", "multiaddr to listen on (repeatable; default all interfaces, random TCP+QUIC ports)")
	flag.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr with /p2p/<id> (repeatable)")
	flag.Parse()

	// A seed node declares its own admission policy with -pow-difficulty; a node
	// that merely joins an existing network omits it and inherits the policy its
	// bootstrap peers enforce (below). Tell the two apart by whether the operator
	// set the flag at all — an explicit -pow-difficulty 0 means "enforce none",
	// distinct from "unset, adopt from bootstrap".
	powDiffSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "pow-difficulty" {
			powDiffSet = true
		}
	})

	logLevelStr := *logLevel
	if *verbose {
		logLevelStr = "debug"
	}
	log, err := newLogger(*logFormat, logLevelStr)
	if err != nil {
		return err
	}

	startedAt := time.Now()

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
		log.Info("ledger reconciled", "event", "ledger.reconcile", "orphan_blobs", rep.OrphanBlobs, "dropped_records", rep.DroppedRecords)
	}

	// Self-defence: resource manager + connection manager + a static blocklist
	// gater. Always on for a node (they act on connection/identity metadata only,
	// never shard content); the blocklist is empty unless -blocklist is given.
	defense := &net.DefenseConfig{
		ConnLow:   *connLow,
		ConnHigh:  *connHigh,
		ConnGrace: *connGrace,
		Log:       log,
	}
	if *blocklist != "" {
		peers, subnets, err := net.LoadBlocklistFile(*blocklist)
		if err != nil {
			return err
		}
		defense.BlockPeers = peers
		defense.BlockSubnets = subnets
		log.Info("blocklist loaded", "path", *blocklist, "peers", len(peers), "subnets", len(subnets))
	}

	h, err := net.NewHost(net.HostConfig{
		ListenAddrs:  listen,
		IdentityPath: filepath.Join(*dataDir, "keys", "node.key"),
		PublicIP:     *publicIP,
		Defense:      defense,
		Log:          log,
	})
	if err != nil {
		return err
	}
	defer h.Close()

	// Tag every subsequent line with this node's peer ID so a shared Loki stream
	// can be filtered per node. Lines emitted before the host exists (config,
	// ledger reconcile) carry only service=revika-node.
	log = log.With("node", h.ID().String())

	srv := net.NewServer(blobs, log)
	srv.SetLedger(led)

	// Storage-load reporter for rebalancing (§3.4): capacity is the usable budget
	// this node advertises, the min of the operator budget (-capacity) and the
	// filesystem's total capacity; used is the ledger's byte total. It backs both
	// the /revika/balance protocol and the metrics surface. A disk probe that the
	// platform does not support leaves capacity to the operator budget (or unknown,
	// in which case the node neither attracts nor sheds shards).
	loadSource := func() (net.LoadReport, error) {
		ls, err := led.Stats()
		if err != nil {
			return net.LoadReport{}, err
		}
		var budget int64
		if u, derr := store.DiskUsage(shardsDir); derr == nil && u.Total > 0 {
			// Usable budget = what we already hold plus what the filesystem can still
			// give us, so capacity tracks real headroom as the disk fills.
			budget = ls.BytesUsed + int64(u.Avail)
		}
		if *capacity > 0 && (budget == 0 || *capacity < budget) {
			budget = *capacity
		}
		if budget < ls.BytesUsed {
			budget = ls.BytesUsed // never report negative free space
		}
		return net.LoadReport{UsedBytes: ls.BytesUsed, CapacityBytes: budget, Shards: ls.Shards}, nil
	}
	srv.SetLoadSource(loadSource)
	if _, derr := store.DiskUsage(shardsDir); errors.Is(derr, store.ErrUnsupported) && *capacity == 0 {
		log.Warn("rebalance: disk-capacity probe unsupported on this platform and no -capacity budget set; load balancing is disabled until a budget is configured")
	}

	// Proof-of-work identity admission: when enabled, an owner's Ed25519 key must
	// be self-certifying (hash under the difficulty target) to store shards, so a
	// banned owner cannot re-mint a fresh identity for free. Off by default.
	//
	// The effective policy is either declared locally (a seed node passes
	// -pow-difficulty/-pow-puzzle) or, for a node that only knows -bootstrap and
	// left -pow-difficulty unset, learned from its bootstrap peers over
	// /revika/params (strictest wins) — the same handshake `revika-ctl connect`
	// uses. So a node joining an existing network inherits the admission bar
	// without the operator re-typing it; only the network's first (seed) node must
	// state the policy.
	effPuzzle, effDiff := *powPuzzle, *powDiff
	if !powDiffSet && len(bootstrap) > 0 {
		fctx, cancel := context.WithTimeout(ctx, time.Duration(len(bootstrap))*bootstrapDialTimeout)
		puzzle, diff, perr := net.FetchPoWPolicy(fctx, h, bootstrap, bootstrapDialTimeout)
		cancel()
		if perr != nil {
			return fmt.Errorf("learn proof-of-work policy from bootstrap: %w", perr)
		}
		if puzzle != "" {
			effPuzzle = puzzle
		}
		effDiff = diff
		if diff > 0 {
			log.Info("proof-of-work policy adopted from bootstrap", "event", "pow.adopt", "puzzle", effPuzzle, "min_bits", diff)
		} else {
			log.Info("proof-of-work policy adopted from bootstrap: none enforced", "event", "pow.adopt")
		}
	}
	if effDiff > 0 {
		if effDiff > 255 {
			return fmt.Errorf("pow-difficulty %d out of range (0-255)", effDiff)
		}
		puzzle, err := cap.PuzzleByName(effPuzzle)
		if err != nil {
			return err
		}
		srv.SetPoW(puzzle, cap.Difficulty(effDiff))
		log.Info("proof-of-work admission enabled", "puzzle", puzzle.Name(), "min_bits", effDiff)
	}

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
		// Answer /revika/root queries from the DHT view, so a client with a
		// connection to this node can resolve a User's signed RootPointer in one
		// round-trip instead of a full DHT walk.
		srv.SetRootResolver(disc)
		if *advertiseOn {
			disc.AdvertiseLoop(ctx)
		}
		go reprovideLoop(ctx, disc, blobs, log)
		// Actively (and observably) discover peer storage nodes over the DHT.
		go discoveryLoop(ctx, disc, log)
		// Repair needs the DHT to find sibling shards and place regenerated ones,
		// so it only runs when the node participates in the DHT.
		if *repairOn {
			go repairLoop(ctx, h, blobs, disc, led, log, *repairEvery)
		}
		// Rebalancing likewise needs the DHT: it discovers candidate targets and
		// relies on provider records to keep a moved shard addressable.
		if *rebalanceOn {
			peersFn := func(ctx context.Context) ([]peer.ID, error) {
				infos, err := disc.FindNodes(ctx, 0)
				if err != nil {
					return nil, err
				}
				ids := make([]peer.ID, len(infos))
				for i, pi := range infos {
					ids[i] = pi.ID
				}
				return ids, nil
			}
			rb := net.NewRebalancer(h, blobs, led, net.LoadSource(loadSource), peersFn, log)
			rb.SetThreshold(*rebalThresh)
			rb.SetCooldown(2 * *rebalEvery)
			go rebalanceLoop(ctx, rb, log, *rebalEvery)
		}
	}

	srv.Register(h)

	// Garbage collector: reclaim shards no owner holds any longer (and, if
	// enabled, expired leases), keeping disk and ledger aligned. Its activity is
	// recorded into gcStats so the metrics server can report it.
	gcStats := net.NewGCStats()
	go gcLoop(ctx, blobs, led, log, *gcInterval, *gcExpired, gcStats)

	// Metrics/status HTTP server (plain HTTP; front it with a TLS-terminating
	// reverse proxy). disc is nil when the DHT is off, which the server handles.
	if *metricsAddr != "" {
		ms := net.NewMetricsServer(h, led, disc, version, buildDate, startedAt, log)
		ms.SetGCStats(gcStats)
		ms.SetPoW(effPuzzle, effDiff)
		ms.SetLoadSource(net.LoadSource(loadSource))
		go func() {
			if err := ms.Serve(ctx, *metricsAddr); err != nil {
				log.Error("metrics: server stopped", "err", err)
			}
		}()
	}

	addrs := make([]string, 0, len(h.Addrs()))
	for _, a := range h.Addrs() {
		addrs = append(addrs, fmt.Sprintf("%s/p2p/%s", a, h.ID()))
	}
	log.Info("revika-node started",
		"event", "node.start",
		"version", version,
		"buildDate", buildDate,
		"peer", h.ID().String(),
		"addrs", addrs,
		"shards", shardsDir,
		"dht", *dhtOn,
		"advertise", *dhtOn && *advertiseOn,
		"bootstrap", len(bootstrap),
		"repair", *dhtOn && *repairOn,
		"metrics", *metricsAddr,
	)

	// Block until interrupted, then shut down cleanly.
	<-ctx.Done()
	log.Info("shutting down", "event", "node.stop")
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
			log.Debug("dht: reproviding shards", "event", "dht.reprovide", "count", len(ids))
			disc.ProvideAll(ctx, ids)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// discoveryLoop waits for the DHT routing table to become ready, then periodically
// asks the DHT for other advertised storage nodes. Newly seen peers are logged by
// the Discovery layer (Discovery.noteDiscovered emits one "discovered node" line
// per genuinely new peer); at debug level each scan also reports the storage-node
// count and routing-table size so a resting network's health is visible. It runs
// until ctx is cancelled.
func discoveryLoop(ctx context.Context, disc *net.Discovery, log *slog.Logger) {
	if err := disc.WaitReady(ctx); err != nil {
		return // ctx cancelled before the routing table filled
	}
	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()
	for {
		sctx, cancel := context.WithTimeout(ctx, discoveryScanTimeout)
		nodes, err := disc.FindNodes(sctx, 0)
		cancel()
		if err != nil {
			log.Debug("discovery: find nodes", "err", err)
		} else {
			log.Debug("discovery: scan complete", "event", "discovery.scan",
				"storage_nodes", len(nodes),
				"routing_table", disc.RoutingTableSize())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// repairLoop is the node-side repair maintenance loop. On each cycle it walks the
// stripes this node participates in (recorded on PUT), probes each stripe's shard
// availability across the network, and — for any stripe that has lost shards but
// still has at least K — regenerates the missing shards onto fresh nodes.
//
// It embodies the "repair is mandatory" principle without breaking the dumb-node
// model: the node holds only the non-confidential stripe descriptor (K, M, sibling
// IDs) and a User-signed repair grant, never the encryption key. Regeneration runs
// purely on ciphertext (erasure.Encode is deterministic, so regenerated shards
// reproduce their exact content addresses) and the grant authorizes re-placing
// them under the owning User's identity with no User online.
//
// There is no coordinator election: every holder of a degraded stripe may act, but
// a small per-stripe jitter plus the fact that regeneration re-fetches survivors
// first (and stores nothing when a sibling already reappeared) makes duplicate work
// rare and always harmless — content-addressed Put and per-owner AddOwner are
// idempotent.
func repairLoop(ctx context.Context, h host.Host, blobs store.Store, disc *net.Discovery, led *ledger.Ledger, log *slog.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runRepair(ctx, h, blobs, disc, led, log, interval)
		}
	}
}

// runRepair performs one repair cycle. Stripe rows that describe the same stripe
// (a node may hold several of a stripe's shards) are deduplicated so each stripe
// is checked once.
func runRepair(ctx context.Context, h host.Host, blobs store.Store, disc *net.Discovery, led *ledger.Ledger, log *slog.Logger, interval time.Duration) {
	rows, err := led.Stripes()
	if err != nil {
		log.Warn("repair: list stripes", "err", err)
		return
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		desc := stripe.Descriptor{K: row.K, M: row.M, Shards: row.Siblings}
		descBytes, err := desc.MarshalBinary()
		if err != nil {
			log.Warn("repair: bad stripe descriptor", "shard", row.ShardID, "err", err)
			continue
		}
		if key := string(descBytes); seen[key] {
			continue
		} else {
			seen[key] = true
		}

		rs := net.NewRepairStore(h, blobs, disc, desc, row.Grant)
		man := pipeline.FileManifest{
			Params: pipeline.Config{Params: erasure.Params{K: row.K, M: row.M}},
			Chunks: []pipeline.ChunkRef{{Shards: desc.Shards}},
		}

		rep, err := repair.Check(ctx, rs, man)
		if err != nil {
			log.Warn("repair: check", "err", err)
			continue
		}
		if rep.Healthy() {
			continue
		}
		st := rep.Chunks[0]
		if !st.Recoverable(row.K) {
			log.Warn("repair: stripe unrecoverable", "present", st.Present, "total", st.Total, "need", row.K)
			continue
		}
		log.Info("repair: degraded stripe", "event", "repair.degraded", "present", st.Present, "total", st.Total, "missing", len(st.Missing))

		// Jitter before acting so multiple holders of the same degraded stripe are
		// unlikely to regenerate simultaneously (any that do are harmless).
		if !sleepJitter(ctx, interval) {
			return
		}
		fixed, err := repair.Repair(ctx, rs, man)
		if err != nil {
			log.Warn("repair: regenerate", "err", err)
		}
		if fixed.Healthy() {
			log.Info("repair: stripe restored", "event", "repair.restored", "total", st.Total)
		} else {
			log.Info("repair: stripe partially repaired", "event", "repair.partial", "still_missing", fixed.MissingShards())
		}
	}
}

// rebalanceLoop is the node-side load-balancing loop (Architecture §3.4). On each
// cycle — after a small jitter to decorrelate concurrent movers — it samples a few
// DHT-discovered peers, and if this node is fuller (by fraction of capacity) than
// the emptiest by more than the threshold, it moves its coldest shards there
// make-before-break. It runs until ctx is cancelled.
//
// Like repair it needs no coordinator: every node runs the same pairwise rule, and
// the per-shard cooldown plus the make-before-break re-provide make concurrent or
// repeated moves harmless. Moves are authorized by each stripe's stored repair
// grant, so the node never needs a User's signing key.
func rebalanceLoop(ctx context.Context, rb *net.Rebalancer, log *slog.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !sleepJitter(ctx, interval) {
				return
			}
			moved, err := rb.RunOnce(ctx, time.Now())
			if err != nil {
				log.Warn("rebalance: cycle", "event", "rebalance.cycle_failed", "err", err)
				continue
			}
			if moved > 0 {
				log.Info("rebalance: cycle complete", "event", "rebalance.cycle", "moved", moved)
			}
		}
	}
}

// sleepJitter sleeps a random duration in [0, min(interval, maxJitter)] to
// decorrelate concurrent repairers, returning false if ctx is cancelled first.
func sleepJitter(ctx context.Context, interval time.Duration) bool {
	const maxJitter = 5 * time.Second
	max := min(interval, maxJitter)
	if max <= 0 {
		return ctx.Err() == nil
	}
	d := time.Duration(mrand.Int64N(int64(max)))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
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
func gcLoop(ctx context.Context, blobs store.Store, led *ledger.Ledger, log *slog.Logger, interval time.Duration, expireLeases bool, stats *net.GCStats) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var prev map[store.ShardID]bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prev = runGC(ctx, blobs, led, log, expireLeases, prev, stats)
		}
	}
}

// runGC performs one GC cycle and returns the set of shards seen collectible
// this cycle (the next cycle's grace baseline). It records the cycle's outcome
// into stats (may be nil) for the metrics server.
func runGC(ctx context.Context, blobs store.Store, led *ledger.Ledger, log *slog.Logger, expireLeases bool, prev map[store.ShardID]bool, stats *net.GCStats) map[store.ShardID]bool {
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
		log.Info("gc: reclaimed shards", "event", "gc.reclaim", "count", freed)
	}
	// Realign disk and ledger: drop records whose blob vanished, recompute quota.
	var rep ledger.ReconcileReport
	if r, err := led.Reconcile(ctx, blobs); err != nil {
		log.Warn("gc: reconcile", "err", err)
	} else {
		rep = r
		if rep.DroppedRecords > 0 {
			log.Info("gc: reconciled", "event", "gc.reconcile", "dropped_records", rep.DroppedRecords, "orphan_blobs", rep.OrphanBlobs)
		}
	}
	stats.Record(freed, rep.DroppedRecords, rep.OrphanBlobs, time.Now())
	return curr
}
