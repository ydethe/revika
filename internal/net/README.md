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
an ephemeral in-memory key for tests), `EnableMDNS`, and `Log`.

**LAN discovery (mDNS).** When `EnableMDNS` is set, `startMDNS` runs an mDNS service
scoped by the `revika` service tag. `mdnsNotifee.HandlePeerFound` best-effort dials
each newly seen LAN peer and logs it once. NAT traversal / transport concerns are
handled by libp2p itself (QUIC + TCP transports, the identify service that
populates peer addresses); revika does not roll its own.

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

Ordering is crash-safe: bytes are stored before ownership is recorded, and on
DELETE the ledger row is removed before the blob — a crash in between leaves an
orphan blob for GC to reclaim, never lost owner data. `handleProbe` returns
`SHA-256(nonce || shardBytes)`. `serverStreamTimeout` (60s) bounds each exchange.

## DHT-backed stores (`placement.go`, `repair.go`)

- `DHTStore` — read-oriented `store.Store` backed by "whoever the DHT says holds
  this shard". `Get`/`Has` look up provider records, connect, and fetch through a
  per-peer `NetStore`, trying providers in turn (stale records tolerated); a shard
  no provider serves maps to `store.ErrNotFound` so the pipeline rebuilds from
  survivors. Writes return `ErrReadOnly`.
- `PlacementStore` (embeds `DHTStore`; is a `stripe.Putter`) — the write-side store
  a User stores through. It spreads shards round-robin across a candidate node set
  so consecutive k+m shards land on distinct nodes (failure-domain diversity).
  `NewPlacementStore` requires a non-empty node set and a signer; `Put`/`PutStripe`
  issue signed writes (`SetGrantExpiry` stamps repair-grant expiry); `Delete` drops
  the owner's claim from every provider best-effort. Reads inherit `DHTStore`.
- `RepairStore` (embeds `DHTStore`) — the store the repair engine
  (`internal/repair`) drives, scoped to a single stripe (carries its `Descriptor`
  and grant). Reads consult the repairing node's **own local store first** then the
  DHT, because `FindProviders` excludes the querier — a node can't discover its own
  shards over the DHT. `Put` places a regenerated shard (via `putGrant`) on a fresh
  discovered node that isn't already a provider, round-robining the start; if every
  node already holds it, that's a no-op success.

## Metrics / status (`metrics.go`, `gcstats.go`)

`MetricsServer` exposes a node's operational state over plain HTTP (meant to sit
behind a TLS-terminating reverse proxy). `NewMetricsServer(h, ledger, disc, version,
started, log)`; `disc` and the GC stats (`SetGCStats`) are optional. `Serve(ctx,
addr)` runs it with graceful shutdown; `Handler()` exposes the mux for tests.
Endpoints:

- `GET /healthz` — liveness.
- `GET /readyz` — readiness (DHT routing table non-empty when the DHT is on; always
  ready otherwise).
- `GET /status` — JSON `Status` snapshot: general info, `StorageInfo` (shards, bytes,
  quota, per-`OwnerInfo` breakdown from the ledger), `NetworkInfo` (connected peers,
  routing-table size, per-`PeerInfo` cartography), and `GCSnapshot`.
- `GET /metrics` — Prometheus text exposition of the same snapshot.

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
