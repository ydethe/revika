# internal/net

revika's libp2p layer. It puts the content-addressed shard store
(`internal/store`) on the wire so a **Node** can serve encrypted shards to remote
**Users**, and a User can treat a remote Node as just another `store.Store`. Every
byte on the wire is an already-encrypted, erasure-coded shard addressed by its
content hash — the Node never learns anything about what it holds. This is the
seam the rest of the architecture is built around: the pipeline and repair layers
run over the network unchanged because a remote node looks identical to a local
`MemStore`/`DiskStore`.

## Wire protocol (`proto.go`)

Two versioned libp2p stream protocols, semantic-versioned so upgrades negotiate
through libp2p's multistream muxer:

- `ShardProtocol` = `/revika/shard/1.1.0` — PUT / GET / HAS / DELETE a shard by
  content address. The `1.1.0` bump added two trailing blobs (stripe descriptor +
  repair grant) after the auth token on PUT.
- `ProbeProtocol` = `/revika/probe/1.0.0` — proof-of-possession challenge/response
  used by repair.
- `BalanceProtocol` = `/revika/balance/1.0.0` — read-only load report used by
  rebalancing (`balance.go`): a peer replies with its self-declared `LoadReport`
  (`used`/`capacity`/`shards` as JSON) so a sampling node can compare normalized
  load before shedding shards to it. Carries no shard content and needs no auth.

**Framing.** One request/response per stream, then the stream closes. A message is
a single opcode/status byte, followed by fixed-width 32-byte IDs and
length-prefixed blobs (4-byte big-endian length). No protobuf, no external codec —
the payloads are opaque and the verb set is tiny. Helpers: `writeByte`/`readByte`,
`writeID`/`readID`, `writeBlob`/`readBlob`, `readNonce`.

Request verbs (`op`): `opPut`, `opGet`, `opHas`, `opDelete`. Response codes
(`status`): `statusOK`, `statusNotFound`, `statusCorrupt`, `statusError` (message
blob follows), `statusUnauthorized`, `statusQuotaExceeded`. `statusToErr` /
`errToStatus` map between status bytes and `store`/`ledger` errors so a NetStore
surfaces the same errors as a local store.

Guards: `MaxShardSize` (64 MiB) caps a single shard/blob allocation, `maxStripeBlob`
(64 KiB) caps a serialized descriptor, `NonceSize` (32) is the probe nonce length.
Exported errors: `ErrRemote`, `ErrUnauthorized`, `ErrQuotaExceeded`.

## libp2p host (`host.go`)

`NewHost(HostConfig)` builds the libp2p host. `HostConfig` carries `ListenAddrs`
(defaulting to all interfaces on OS-assigned TCP + QUIC-v1 ports), `IdentityPath`
(a persistent Ed25519 identity loaded or generated+persisted at 0600; empty means
an ephemeral in-memory key for tests), `PublicIP`, `Defense`, and `Log`.

**Public IP / NAT.** A node behind NAT only observes private/unspecified listen
addresses, so WAN peers cannot dial it. Set `HostConfig.PublicIP` (the node's
`-public-ip` flag) to the node's externally reachable IPv4/IPv6 address:
`publicAddrsFactory` then installs a libp2p `AddrsFactory` that advertises, for
every listen address, a public variant with the IP swapped for `PublicIP` and the
transport/port preserved (listed first so peers prefer the routable address). This
assumes the public port equals the bound port (a 1:1 port forward, which holds for
fixed `-listen` ports mapped straight through). The public variants flow through to
the DHT and to `/status`'s bootstrap strings.

**Discovery / transport.** Peer discovery is the Kademlia DHT (see `Discovery`
below); there is no LAN/mDNS path. NAT traversal / transport concerns are handled
by libp2p itself (QUIC + TCP transports, the identify service that populates peer
addresses); revika does not roll its own.

## Self-defence (`defense.go`)

A node is dumb about *content*, not about its own availability. `HostConfig.Defense`
(a `*DefenseConfig`) installs three anti-DoS/DDoS layers on `libp2p.New`; all inspect
only connection/identity metadata — a peer ID, an IP, a connection count — never shard
bytes, so the untrusted-blob-store model holds. Nil (tests) leaves libp2p's defaults.

- **`ResourceManager`** — an explicit fixed limiter from `rcmgr.DefaultLimits.AutoScale()`
  (scaled to the host's memory + FD budget), giving hard per-scope caps on memory, streams,
  and connections so one peer can't exhaust the host.
- **`ConnManager`** — soft low/high connection watermarks (`defaultConnLow`/`defaultConnHigh`
  = 64/192) with a grace period (`defaultConnGrace` = 30s); once connections exceed the high
  mark the least-useful ones (past grace) are trimmed toward the low mark. `ConnHigh <= 0`
  disables it.
- **`ConnectionGater`** (`blocklistGater`) — a static, operator-supplied **peer-ID / subnet
  blocklist**. Installed only when non-empty. It denies a blocked peer whether we dial it
  (`InterceptPeerDial`/`InterceptAddrDial`) or it dials us (`InterceptAccept` on IP before
  the handshake, `InterceptSecured` on peer ID after), so an abusive peer is refused at the
  transport layer before any protocol handler runs.

`ParseBlocklist`/`LoadBlocklistFile` parse a blocklist file: one entry per line, each a
libp2p peer ID, a CIDR (`203.0.113.0/24`), or a bare IP (kept as a /32 or /128 host route);
`#` starts a whole-line or inline comment. `revika-node -blocklist <file>` wires it in;
`-conn-low`/`-conn-high`/`-conn-grace` tune the connection manager.

These are *connection/flow* caps that complement the ledger's *storage* cap (per-owner
quota). **Still planned:** per-peer/per-owner rate limiting on the write verbs (a token
bucket keyed on the Ed25519 owner) with a `statusRateLimited` response. See
Architecture.md §3.1/§5.

## DHT discovery (`dht.go`)

`Discovery` is revika's Kademlia DHT layer for WAN peer, node-service, and shard
discovery with no central server.

- **Private network.** The DHT protocol prefix is `revikaDHTPrefix` = `/revika`
  (stream protocol `/revika/kad/1.0.0`), isolating revika's DHT from the public
  IPFS DHT — revika peers only exchange routing state and provider records with
  each other.
- **Modes** (`DHTMode`): `DHTModeAuto` (server if publicly reachable, else client),
  `DHTModeClient` (query only; for the CLI / NAT'd peers), `DHTModeServer` (full
  participant; the Node mode).
- `NewDiscovery(ctx, h, DiscoveryConfig)` builds the DHT, connects to
  `cfg.Bootstrap` multiaddrs, and bootstraps the routing table. `Bootstrap` is
  best-effort per peer but errors if bootstrap peers were given and none reached.

Content routing: `shardCID` wraps a `ShardID` (already a SHA-256 digest) as a
SHA2-256 multihash under a CIDv1 raw codec. `Announce`/`ProvideAll` publish
provider records ("this host holds this shard"); `FindProviders` returns peers that
announced a given shard (self excluded). Node-service discovery uses the
`storageNamespace` rendezvous (`revika/storage/1.0.0`): `AdvertiseLoop` keeps this
host advertised as a storage node; `FindNodes` discovers candidate storage targets.
`noteDiscovered` logs each peer once. `RoutingTableSize` / `WaitReady` gauge and
wait on routing-table readiness (bootstrap populates it asynchronously after the
identify handshake). `Close` shuts the DHT down before the host.

## Client store (`client.go`)

`NetStore` is a `store.Store` (and `stripe.Putter`) whose backend is a remote Node
over libp2p. It holds no per-call state and is safe for concurrent use — each op
opens a fresh stream, exchanges one request/response, and closes it.

- `NewNetStore(h, peer)` — unsigned; for reads or ledger-less nodes.
- `NewNetStoreSigned(h, peer, signer)` — attaches the User's Ed25519 signing key so
  PUT/DELETE carry an authorization token. Reads never sign.
- `Put` / `PutStripe` (adds the stripe descriptor + a freshly built repair grant via
  `stripe.BuildGrant`) / `putGrant` (repair path: authorized by grant, not owner
  token) / `Get` / `Has` / `Delete` / `Probe`.

Every read self-verifies: `Get` rehashes returned bytes (mismatch → `store.ErrCorrupt`)
and PUT verifies the node echoed the true content address — a lying node is caught.
`Probe` sends a fresh random nonce and constant-time-compares the node's
`SHA-256(nonce || bytes)` proof against the caller's own copy, confirming survival
without shipping the shard back. `Connect` is a convenience to dial a node by
`peer.AddrInfo`.

## Auth tokens (`auth.go`)

How a Node learns *who* is issuing a write without trusting the ephemeral libp2p
peer identity of the client.

    token = ownerPubKey(32) || timestamp(8, big-endian) || sig(64)
    sig   = Ed25519-Sign( op || shardID(32) || nodePeerID || timestamp )

The signature binds the operation, the exact shard, the **target node**, and a
timestamp. Binding the node scopes a token to one Node (a token captured by node X
can't be replayed to node Y); the timestamp (bounded by `tokenSkew` = 5 min) lets a
Node reject stale tokens. Because writes are owner-scoped and idempotent, replay
within the window is harmless. `buildToken` (client) and `verifyToken` (server,
returns the owner public-key bytes = the ledger owner identity) hash the identical
`tokenPayload` bytes. `authTokenSize` is the fixed wire length.

## Node server (`server.go`)

`Server` serves the shard and probe protocols for the Node role, backed by a
`store.Store`. It is the whole of a Node's behaviour — it never decrypts,
interprets, or trusts payloads.

- `NewServer(store, log)`, then `Register(h)` installs the two stream handlers.
- `SetAnnouncer(Announcer)` — attaches a DHT announcer (`*Discovery` satisfies the
  `Announcer` interface) so every accepted shard is advertised as a provider record
  in the background (`announce`, outliving the request stream).
- `SetLedger(*ledger.Ledger)` — turns on authorization. With a ledger: PUT requires
  a valid signed owner token *or* a valid repair grant naming the shard (which
  authorizes a regenerated copy under the granting User's ownership) and is
  quota-checked; DELETE drops only the caller's own ownership claim and physically
  removes the blob only when the last owner leaves; the erasure context (descriptor
  + grant) is recorded so the node can later help repair the stripe. Without a
  ledger the server is an unauthenticated blob store (tests / legacy single-node).
- `SetPoW(puzzle, difficulty)` — turns on **proof-of-work identity admission**. When
  difficulty > 0, the owner a PUT would be recorded under (from the token, or the
  repair grant) must be a *self-certifying* identity — its `cap.Puzzle` digest must
  have at least `difficulty` leading zero bits (`cap.MeetsPoW`) — or the PUT is refused
  with `ErrUnauthorized`. This makes an identity ban bite: replacing a banned owner
  costs ~`2^difficulty` puzzle evaluations, not milliseconds. Verification is one hash.
  Only PUT is gated (the write/abuse vector); DELETE stays ungated (owner-scoped, and
  gating it would strand data for owners minted below a later-raised bar). Difficulty
  and puzzle are local operator policy, so a client must `keygen` with a matching puzzle
  and difficulty ≥ the node's — a self-certifying key only verifies against the exact
  puzzle it was minted for. Zero (the default) disables the check. See
  `internal/cap/pow.go` and `revika-node -pow-difficulty/-pow-puzzle`.

Ordering is crash-safe: bytes are stored before ownership is recorded, and on
DELETE the ledger row is removed before the blob — a crash in between leaves an
orphan blob for GC to reclaim, never lost owner data. `handleProbe` returns
`SHA-256(nonce || shardBytes)`. `serverStreamTimeout` (60s) bounds each exchange.

**Planned abuse controls.** Beyond the per-owner storage quota the ledger already
enforces, the server is the place for a *flow* cap: a per-peer and per-owner token bucket
on `PUT`/`DELETE` (keyed on the Ed25519 owner from `verifyToken`), with anonymous
`GET`/`HAS`/`PROBE` limited per-peer/IP only, surfaced by a new `statusRateLimited`
response code. Transport-level blocking already lives in the host's `ConnectionGater`
(see **Self-defence** above); together with the quota they form a node's acceptable-use
enforcement. See Architecture.md §3.1/§5.

**Planned — proof-of-work difficulty advertisement.** Difficulty is per-node local policy
(`SetPoW`), so a client storing across nodes must mint at the *max* difficulty among them
under a matching puzzle. Today `put` does not learn a node's requirement in advance, so a
mismatch surfaces late as an `ErrUnauthorized` on the failed `PUT`. Planned: the node
advertises its `(puzzle, min difficulty)` — e.g. a `/revika/params` query or a field on the
DHT provider/storage advertisement — so the client checks it up front and fails fast with an
actionable "re-run keygen at difficulty ≥ N with puzzle X" message instead of a bare
authorization error. See Architecture.md §5.

## DHT-backed stores (`placement.go`, `repair.go`)

- `DHTStore` — read-oriented `store.Store` backed by "whoever the DHT says holds
  this shard". `Get`/`Has` look up provider records, connect, and fetch through a
  per-peer `NetStore`, trying providers in turn (stale records tolerated); a shard
  no provider serves maps to `store.ErrNotFound` so the pipeline rebuilds from
  survivors. Writes return `ErrReadOnly`.
- `PlacementStore` (embeds `DHTStore`; is a `stripe.Putter`) — the write-side store
  a User stores through. It spreads shards across a candidate node set so consecutive
  k+m shards land on distinct nodes (failure-domain diversity), delegating the choice
  to a pluggable `placement.Selector` (see [`internal/placement`](../placement/README.md);
  default round-robin, swappable via `SetSelector`). `NewPlacementStore` requires a
  non-empty node set and a signer; `Put`/`PutStripe` issue signed writes
  (`SetGrantExpiry` stamps repair-grant expiry); `Delete` drops the owner's claim from
  every provider best-effort. Reads inherit `DHTStore`.
- `RepairStore` (embeds `DHTStore`) — the store the repair engine
  (`internal/repair`) drives, scoped to a single stripe (carries its `Descriptor`
  and grant). Reads consult the repairing node's **own local store first** then the
  DHT, because `FindProviders` excludes the querier — a node can't discover its own
  shards over the DHT. `Put` places a regenerated shard (via `putGrant`) on a fresh
  discovered node that isn't already a provider, round-robining the start; if every
  node already holds it, that's a no-op success.

## Rebalancing (`balance.go`, `rebalance.go`)

Corrects the *standing* shard distribution so that, asymptotically, every node
holds the same **fraction of its own capacity** — not the same shard count
(Architecture §3.4). Repair only ever *adds* a shard; rebalancing *moves* one.

- `LoadReport` / `LoadSource` / `QueryLoad` (`balance.go`) — a node's `LoadSource`
  closure reports its `LoadReport` (`used`/`capacity`/`shards`); `SetLoadSource`
  wires it to both the `BalanceProtocol` handler and the `MetricsServer`.
  `QueryLoad(ctx, h, peer)` fetches a peer's report. `LoadReport.Load()` projects
  onto [`placement.Load`](../placement/README.md) for the `Frac`/`Free` math.
- `Rebalancer` (`rebalance.go`) — one round of `RunOnce(ctx, now)`: report our
  load; sample a few peers (a pluggable `peers` func, e.g. over `Discovery.FindNodes`);
  `QueryLoad` each and pick the emptiest (power-of-k choices); `placement.OffloadBytes`
  decides the byte budget (0 within the threshold dead-band — the anti-thrash guard);
  then move the coldest shards (`ledger.ColdShards`) **make-before-break** — `putGrant`
  to the peer first (the peer records ownership + re-announces the CID), then
  `release` (drop the local blob + `ledger.DropRecord`). A per-shard cooldown pins a
  just-moved shard so it can't bounce back; a peer's `statusQuotaExceeded` stops
  shedding to it. Moves are authorized by the stripe's stored repair grant, so no
  User signing key is needed — the same trust path as repair.

  Two guards make the diffusion path safe against a shard-absorbing node (one that
  advertises itself empty to attract shards, then drops them — Architecture §3.4):
  - **Stripe concentration cap** (`peerStripeLoad`): before shedding a shard, count
    (via `Has`) how many of its stripe's siblings the target already holds and skip
    the move if adding this one would give a single node more than `m` shards of the
    stripe — the point past which that node's loss alone makes the stripe
    unrecoverable (any `k` of `k+m` reconstruct). Best-effort: a node may under-report
    `Has`, but the release gate below still bars durability loss.
  - **Proof-gated release** (`confirmStored`): after the `putGrant` succeeds, the
    source `Probe`s the peer with a fresh CSPRNG nonce and only calls `release` once
    the peer proves it holds the exact bytes. A peer that can't prove possession keeps
    us from dropping our copy — a proof *mismatch* also stops shedding to it this
    round; a probe transport error just keeps this shard. This wires the `Probe`
    primitive into the write path, so the source never surrenders its only durable
    copy to a lying receiver.

## Metrics / status (`metrics.go`, `gcstats.go`)

`MetricsServer` exposes a node's operational state over plain HTTP (meant to sit
behind a TLS-terminating reverse proxy). `NewMetricsServer(h, ledger, disc, version,
buildDate, started, log)`; `disc`, the GC stats (`SetGCStats`), the proof-of-work
policy (`SetPoW`), and the storage-load reporter (`SetLoadSource`, feeding the
capacity/free/load fields) are optional. `Serve(ctx, addr)` runs it with graceful
shutdown; `Handler()` exposes the mux for tests. Endpoints:

- `GET /healthz` — liveness.
- `GET /readyz` — readiness (DHT routing table non-empty when the DHT is on; always
  ready otherwise).
- `GET /status` — JSON `Status` snapshot: general info (including `build_date`, the
  `bootstrap` strings, and the `PoWInfo` admission policy — enabled, puzzle name,
  difficulty bits), `StorageInfo` (shards, bytes, quota, the rebalancing signal
  `capacity_bytes`/`free_bytes`/`load` when a load source is set, and a per-`OwnerInfo`
  breakdown from the ledger), `NetworkInfo` (connected peers, routing-table size,
  per-`PeerInfo` cartography), and `GCSnapshot`. `bootstrap` mirrors `listen_addrs` with
  the node's `/p2p/<peer-id>` appended — each entry is ready to paste into `revika-ctl -bootstrap`.
- `GET /metrics` — Prometheus text exposition of the same snapshot, including
  `revika_build_info{version,build_date}`, `revika_bootstrap_info{addr}`,
  `revika_pow_enabled{puzzle}`, `revika_pow_difficulty_bits`, and the load gauges
  `revika_capacity_bytes` / `revika_free_bytes` / `revika_load_ratio`.

`GCStats` (`gcstats.go`) is a thread-safe counter shared between a node's GC loop
(`Record`) and the MetricsServer (`Snapshot` → `GCSnapshot`), reporting cycles run,
shards reclaimed, dropped orphan records, and last-run time.

## How it fits together

A **Node** (`cmd/revika-node`) builds a host, a `Discovery` in server mode, a
`Server` wired to a disk store + ledger + the Discovery announcer, and optionally a
MetricsServer. A **User** (`cmd/revika-ctl`) builds a client host, a `Discovery` in
client mode, finds storage nodes (`FindNodes`), and runs the pipeline over a
`PlacementStore` (write) / `DHTStore` (read). Repair runs on any node over a
`RepairStore`, moving and regenerating ciphertext shards it can never decrypt.
