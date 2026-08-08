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

- `ShardProtocol` = `/revika/shard/1.2.0` — PUT / GET / HAS / DELETE a shard by
  content address. A PUT frame carries the data, three trailing blobs (auth token,
  stripe descriptor, repair grant) after it, and a final **`MoveReason`** byte
  declaring *why* a shard is being written: `ReasonClient` (0, owner-initiated write,
  carries a token), `ReasonRepair` (1, grant-gated regeneration — schedule-exempt,
  may burst after node loss), or `ReasonRebalance` (2, grant-gated diffusion move —
  policed by the abuse detector). The reason carries only the reason, no load
  fraction. revika is pre-release, so the wire carries no back-compat guarantee: only
  the current version is served and dialed, and libp2p's multistream muxer fails
  negotiation against a peer on a different version rather than mis-framing.
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
blob follows), `statusUnauthorized`, `statusQuotaExceeded`, `statusRateLimited`
(owner over the per-owner write-rate cap; transient, retry after the bucket
refills). `statusToErr` / `errToStatus` map between status bytes and `store`/`ledger`
errors so a NetStore surfaces the same errors as a local store.

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
- **`ConnectionGater`** (`blocklistGater`) — a **peer-ID / subnet blocklist**. It denies a
  blocked peer whether we dial it (`InterceptPeerDial`/`InterceptAddrDial`) or it dials us
  (`InterceptAccept` on IP before the handshake, `InterceptSecured` on peer ID after), so an
  abusive peer is refused at the transport layer before any protocol handler runs. The subnet
  list is fixed at construction (operator policy); the peer-ID set is **mutable and
  mutex-guarded** so the runtime abuse detector can extend it (`addPeer`) while the gater is live.

`ParseBlocklist`/`LoadBlocklistFile` parse a blocklist file: one entry per line, each a
libp2p peer ID, a CIDR (`203.0.113.0/24`), or a bare IP (kept as a /32 or /128 host route);
`#` starts a whole-line or inline comment. `revika-node -blocklist <file>` wires it in;
`-conn-low`/`-conn-high`/`-conn-grace` tune the connection manager.

**Runtime, persistent blocklist (`Blocklister`).** The gater alone is static and forgets its
bans on restart. `Blocklister` wraps it into a *mutable, persistent* blocklist: it seeds from
the operator's `-blocklist` (peers + subnets) **unioned** with a flat auto-blocklist file the
detector appended to on prior runs, so a peer banned in one run stays banned across restarts.
`Block(p, reason)` bans at runtime — it extends the live gater (refusing the peer's *future*
dials), appends the peer ID to the auto file as one `ParseBlocklist`-compatible line (single
`O_APPEND` write; reason kept as a trailing comment), and closes any live connection to the
peer via `host.Network().ClosePeer` (the gater alone would leave an established connection
open). It is idempotent (an already-blocked peer is a no-op). `SetHost` hands it the live host
after `NewHost`; construction happens before the host exists, so the gater is built first and
the host adopts it via `DefenseConfig.Blocklister`. `revika-node -blocklist-auto <file>` sets
the path (default `<data>/blocklist.auto`, `off` disables persistence). `Block` only ever
appends peer IDs — identity is the unit the detector acts on; subnet rules stay operator policy.

These are *connection/flow* caps that complement the ledger's *storage* cap (per-owner
quota). The remaining *flow* cap — per-owner rate limiting on the write verbs — now ships
as an optional `OwnerRateLimiter` (see **Write-verb rate limiting** below). See
Architecture.md §3.1/§5.

## Write-verb rate limiting (`ratelimit.go`)

`OwnerRateLimiter` is an optional per-owner token bucket on the write verbs, the *flow*
cap that complements the ledger's per-owner storage *volume* quota. Each owner (the
Ed25519 key recovered from a PUT/DELETE auth token) gets a bucket of `burst` tokens that
refills at `rate` tokens/second; a write costs one token, and a write that finds the bucket
empty is refused with `statusRateLimited` (`ErrRateLimited`) — transient, so the caller may
retry once tokens refill. It acts only on the owner identity, never decrypting or
interpreting a shard, so the untrusted-blob-store trust model is untouched.

- `NewOwnerRateLimiter(rate, burst)` returns `nil` when `rate <= 0` (disabled), and a nil
  `*OwnerRateLimiter` meters nothing — so `Allow` is safe to call unconditionally.
- `Allow(owner, now)` credits lazily accrued tokens (capped at `burst`), charges one, and
  reports admission. An **empty owner is never metered**: the grant-authorized maintenance
  flows (repair regeneration, rebalance moves) carry no owner token, so — exactly as
  proof-of-work admission exempts them — throttling them (mandatory repair; rebalance is
  policed separately by the `AbuseMonitor`) would strand durability.
- Idle, full buckets are pruned (`pruneLocked`, at most once per `rateBucketIdle` = 10m) so
  the map cannot grow unbounded; a full bucket is indistinguishable from a fresh one, so the
  drop is lossless.

`Server.SetRateLimiter` wires it in: `handlePut` meters only the token branch (a fresh
owner-initiated write, after the PoW check), and `handleDelete` meters after the owner is
verified. It is a **local** defence, wired from `revika-node -write-rate/-write-burst`
(off by default, `-write-rate 0`) and — like the abuse-detector tuning — never inherited
from bootstrap.

## Maintenance-abuse detection (`abuse.go`)

`AbuseMonitor` is a node's local defence against a peer that abuses the two
grant-authorized *maintenance* flows it drives against this node — rebalance moves and
possession probes. It acts only on connection/identity metadata (which peer, how often),
never decrypting or interpreting a shard, and bans through a `peerBlocker` (`*Blocklister`).
Two independent triggers:

- **Off-schedule rebalancing (fast-side only).** A well-behaved peer initiates a rebalance
  sweep about once per cluster interval. The server tags each grant-gated PUT it receives with
  its `MoveReason`; on a `ReasonRebalance` move `RecordRebalanceMove(peer, now)` fires. One
  sweep is a burst of back-to-back PUTs, so moves within a **coalesce** window fold into a
  single event; the *first* event only sets a baseline. A new sweep whose gap since the prior
  sweep is `< interval − tolerance` is **too fast** → the peer is banned on that first
  violation. Too-slow is fine (a lightly loaded peer may never shed). The **tolerance** (a
  required duration, default 10m) absorbs jitter — a strict comparison would false-positive
  constantly. The yardstick is the *effective* rebalance interval, whether declared locally or
  inherited from bootstrap, so a joiner polices against the same cadence it runs. Interval 0
  disables the check (nothing to measure against).
- **Possession lies (strike budget).** A peer that claims to hold a shard but fails a
  fresh-nonce possession proof (the make-before-break check in `rebalance.go`) is lying about
  durability. A single failure can be a race, so `RecordPossessionLie(peer, now)` accrues
  **decaying** strikes (default window 24h) and bans at a threshold (default 3).

Tuning is via `AbuseConfig` (zero fields take built-in defaults through `withDefaults`;
coalesce defaults to `min(interval/4, 5m)`) wired from `revika-node`'s
`-rebalance-abuse-tolerance/-coalesce/-strikes/-decay`. These configure a **local** defence,
so — unlike PoW/repair/rebalance policy — they are *never* inherited by or ignored on a joining
node; every node tunes its own. The detector is safe for concurrent use (the shard server feeds
it from many stream handlers, the rebalancer from its loop). Banning by identity is weak while
identities are free to mint (global anti-Sybil is deferred — Architecture §5), but with
proof-of-work identities it is not free to evade. Repair-engine probe strikes
(`internal/repair`) are a deferred follow-up (they would require threading the monitor into
another package); today only the in-package rebalance possession check feeds strikes.

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

## Root pointer publication (`root.go`, `root_proto.go`)

The one mutable anchor per User — `manifest.RootPointer` (`owner-pubkey → root cap`,
signed, monotonic `Seq`) — is published IPNS-style so a namespace is
network-visible and multi-device (Architecture §4). Two complementary paths:

- **DHT value record (`root.go`).** `Discovery.PutRoot(ctx, rp)` publishes under
  `/revika/<owner-pubkey>` after stripping the cap to its **verify projection**
  (`rp.Root = rp.Root.VerifyCap().ReadCap()`) — the public record carries *no*
  decryption key, yet the same signature still verifies because `RootPointer` signs
  over exactly that projection. `Discovery.GetRoot(ctx, owner)` resolves it
  (`routing.ErrNotFound` → `ok=false`) and re-verifies signature + owner binding.
  `rootValidator` (registered via `dht.NamespacedValidator(RootNamespace, …)`) makes
  the DHT itself enforce the rules: `Validate` rejects any record whose key doesn't
  name the signing owner or whose signature fails; `Select` keeps the **highest
  `Seq`**, so a node cannot serve a rolled-back root. An equal-`Seq` fork (two
  devices sharing one owner key that both advanced to the same sequence against
  different roots) is broken by a **total byte-order** on the encoded record, *not*
  first-seen — so every replica/reader converges on the same visible tip and the
  losing device folds its change in on its next write. DHT records expire after the
  48h max age, so `RepublishRootLoop(ctx, load, every)` re-puts at ~12h.
- **Sealed self-root companion (`root.go`).** For multi-device reconciliation
  (Architecture §3.7.1), each commit also publishes a `manifest.FullRootRecord` under
  `/revika-fullcap/<owner>` (`FullRootNamespace`): the **full** root cap (AES key
  retained) sealed to the owner's own ML-KEM key, so the User's *other* devices can
  decrypt and three-way-merge — the public verify-root above stays key-stripped.
  `Discovery.PutFullRoot(ctx, r)` publishes it; `Discovery.GetFullRoot(ctx, owner,
  priv, pub, verifyRoot)` resolves it, opens the seal with the owner ML-KEM keys, and
  **binds** the opened cap to the presented verify-root (`companion.VerifyCap() ==
  verifyRoot`) so a stale or forged companion is rejected rather than merged.
  `fullRootValidator` (registered via `dht.NamespacedValidator(FullRootNamespace, …)`)
  gates it exactly as `rootValidator` does the verify-root — owner-binding + signature,
  highest-`Seq` with a byte-order tie-break — but never opens the seal (confidentiality
  is the ML-KEM layer's job). For the **read-revocable device model** (§3.7.2) the same
  companion is sealed once per authorized device (`manifest.SealFullRootFor`), so a
  revoked device's ML-KEM key no longer opens it.
- **Device-authorization record (`deviceauth.go`).** The owner-signed set of ML-KEM device
  pubkeys currently allowed to read (`device.Auth`) is mirrored to the DHT under
  `/revika-devices/<owner>` (`DeviceAuthNamespace`) — the *policy* half of read revocation
  (the sealed companion above is the *mechanism*). `Discovery.PutDeviceAuth`/`GetDeviceAuth`
  publish/resolve it; `deviceAuthValidator` gates it exactly like `rootValidator` (owner-key
  binding + signature, highest-`Seq` `Select` for anti-rollback so a stale record can never
  re-authorize a revoked device). It carries only public keys + an owner signature, so it is
  safe in the clear.
- **Direct node stream (`root_proto.go`).** `/revika/root/1.0.0` lets a client that
  already has a node connection fetch a root in one round-trip (or a DHT-less
  single-node/test setup serve one). `QueryRoot(ctx, h, peer, owner)` is the client
  half; a node wires `Server.SetRootResolver(disc)` and answers from its DHT view via
  `handleRoot` (same status-byte + length-prefixed framing as the shard protocol,
  miss → `statusNotFound`). Read-only and unauthenticated — a `RootPointer` is a
  public, signed, key-stripped record.

The provider seam (`internal/provider.DHTRootStore`/`MultiRootStore`) rides on
`Discovery` structurally via a local `RootPublisher` interface, so `provider` never
imports `net`. `revika-ctl` publishes on every `cp`/`rm`/`revoke` commit (DHT mirror
behind the durable local `root.json`) and resolves a published root with
`ls -owner <pubkey-file>` — a verify-only inspector (integrity/liveness/revocation
detection), never a decryption path.

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
  repair grant) must be a *self-certifying* identity — its `cap.Argon2idPuzzle` digest must
  have at least `difficulty` leading zero bits (`cap.MeetsPoW`) — or the PUT is refused
  with `ErrUnauthorized`. This makes an identity ban bite: replacing a banned owner
  costs ~`2^difficulty` puzzle evaluations, not milliseconds. Verification is one hash.
  Only PUT is gated (the write/abuse vector); DELETE stays ungated (owner-scoped, and
  gating it would strand data for owners minted below a later-raised bar). Difficulty
  is local operator policy, so a client must `keygen` with difficulty ≥ the node's; the
  puzzle is always Argon2id, so there is nothing to negotiate. Zero (the default)
  disables the check. See `internal/cap/pow.go` and `revika-node -pow-difficulty`.
- `SetMaintenancePolicy(repair, rebalance)` — records the effective repair/rebalance
  cadence the node runs so `/revika/params` can advertise it for policy inheritance (it
  does not itself schedule anything; the loops live in `cmd/revika-node`).
- `SetAbuseMonitor(*AbuseMonitor)` — wires the maintenance-abuse detector. On a
  grant-authorized PUT tagged `ReasonRebalance` (no owner token, stripe descriptor + grant
  present) `handlePut` calls `RecordRebalanceMove` so the detector can police a peer that
  rebalances against this node too fast. Every PUT frame carries the reason byte; an unknown
  value defaults to `ReasonRepair` and is never counted as a rebalance move.
- `SetRateLimiter(*OwnerRateLimiter)` — wires the optional per-owner write-verb rate cap
  (see **Write-verb rate limiting**). `handlePut` meters the token branch (after the PoW
  check) and `handleDelete` meters the verified owner; an over-rate write is refused with
  `statusRateLimited` before any store/ledger work. Grant-authorized maintenance writes are
  exempt. Nil (the default) meters nothing.

Ordering is crash-safe: bytes are stored before ownership is recorded, and on
DELETE the ledger row is removed before the blob — a crash in between leaves an
orphan blob for GC to reclaim, never lost owner data. `handleProbe` returns
`SHA-256(nonce || shardBytes)`. `serverStreamTimeout` (60s) bounds each exchange.

**Abuse controls.** Beyond the per-owner storage quota the ledger enforces, the server
carries a *flow* cap: an optional per-owner token bucket on `PUT`/`DELETE` (keyed on the
Ed25519 owner from `verifyToken`), surfaced by the `statusRateLimited` response code — see
**Write-verb rate limiting** above (`SetRateLimiter`). Transport-level blocking lives in the
host's `ConnectionGater` (see **Self-defence**); together with the quota they form a node's
acceptable-use enforcement. **Still planned:** rate-limiting the anonymous read verbs
(`GET`/`HAS`/`PROBE`) per-peer/IP. See Architecture.md §3.1/§5.

**Node policy advertisement (`params.go`, `/revika/params/1.0.0`).** A node answers a
read-only, unauthenticated `/revika/params` query (registered by `Register`, same
one-request/response framing as balance) with a `NodeParams` envelope carrying the whole
cluster-facing policy so a new participant inherits it instead of the operator re-typing it:

- **`PoW`** (`PoWInfo`) — admission: the minimum difficulty (the puzzle is always Argon2id, so
  it is not carried on the wire), or a zeroed policy when admission is off. Difficulty is
  per-node local policy (`SetPoW`); a client must mint an owner identity satisfying the node it
  stores through, or the mismatch surfaces late as an `ErrUnauthorized` on the failed `PUT`.
- **`Repair`** (`RepairInfo`) / **`Rebalance`** (`RebalanceInfo`) — the maintenance cadence
  (`Enabled` + `Interval`, plus the rebalance `Threshold`) this node actually runs. A node with
  the DHT off advertises them disabled regardless of its flags (repair/rebalance need the DHT).

`QueryParams(ctx, h, peer)` is the client half; `FetchNodePolicy(ctx, h, bootstrap,
dialTimeout)` (which replaced the PoW-only `FetchPoWPolicy`) reconciles the envelope across a
bootstrap set into the single policy a new participant adopts: PoW **strictest wins** (max
difficulty, one consistent puzzle — a disagreement among PoW-enforcing nodes is a hard error),
repair **any-enabled + shortest interval**, rebalance **any-enabled + shortest interval +
smallest threshold**; it fails closed when no node answers. Two callers drive it through the
same code path: `revika-ctl connect` (uses only the `PoW` field, to grind an admissible
identity saved to the workspace config) and a joining `revika-node` that knows only `-bootstrap`
(to inherit the full admission + maintenance policy — only the network's seed node states it).
It reveals only the node's own local policy, never shard content, so it needs no owner token.
The `NodeParams` envelope leaves room to advertise more (e.g. suggested erasure `k`/`m`) without
a protocol bump. See Architecture.md §5.

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
  node already holds it, that's a no-op success. `SetVerifyPossession(true)` (opt-in,
  from `revika-node -repair-verify`) hardens the survival check: instead of trusting a
  remote holder's `HAS` presence byte, `Has` fetches the shard and lets the content
  address self-verify (`hash == ID`), so a node that lies "I hold it" cannot fake
  availability — an unfetchable/corrupt shard counts as **missing** and repair
  regenerates it. It costs a shard download per remote check, so it is off by default;
  a local hit short-circuits either way. Being a local defence, it is never inherited
  from bootstrap.

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
    copy to a lying receiver. A proven possession *lie* (the probe returns `!ok` with
    no transport error) also feeds `AbuseMonitor.RecordPossessionLie` via the optional
    `SetAbuseMonitor`, accruing a strike against the receiver.

  A rebalancer's own PUTs carry `ReasonRebalance`, so the *receiving* node's
  `AbuseMonitor` can measure how often this node rebalances against it (see
  **Maintenance-abuse detection** above) — the source-side guards above protect *this*
  node's durability; the reason tag lets a peer protect *itself* from an over-eager mover.

## Metrics / status (`metrics.go`, `gcstats.go`)

`MetricsServer` exposes a node's operational state over plain HTTP (meant to sit
behind a TLS-terminating reverse proxy). `NewMetricsServer(h, ledger, disc, version,
buildDate, started, log)`; `disc`, the GC stats (`SetGCStats`), the proof-of-work
policy (`SetPoW`), the maintenance policy (`SetMaintenance`, the effective
repair/rebalance cadence this node runs and advertises), the served stream-protocol
versions (`SetProtocols`, fed `Server.Protocols()` so `/status` and `/metrics` report
the wire versions this node speaks), the storage-load reporter
(`SetLoadSource`, feeding the capacity/free/load fields), and the peer geolocator
(`SetGeolocator`, powering the `/nodes` map) are optional. `Serve(ctx, addr)`
runs it with graceful shutdown; `Handler()` exposes the mux for tests. Endpoints:

- `GET /healthz` — liveness.
- `GET /readyz` — readiness (DHT routing table non-empty when the DHT is on; always
  ready otherwise).
- `GET /status` — JSON `Status` snapshot: general info (including `build_date`, the
  `bootstrap` strings, the served `protocols` list, and the `PoWInfo` admission policy —
  enabled, puzzle name, difficulty bits), `StorageInfo` (shards, bytes, quota, the rebalancing signal
  `capacity_bytes`/`free_bytes`/`load` when a load source is set, and a per-`OwnerInfo`
  breakdown from the ledger), the `RepairInfo`/`RebalanceInfo` maintenance policy, `NetworkInfo`
  (connected peers, routing-table size, per-`PeerInfo` cartography), and `GCSnapshot`.
  `bootstrap` mirrors `listen_addrs` with the node's `/p2p/<peer-id>` appended — each entry is
  ready to paste into `revika-ctl -bootstrap`.
- `GET /nodes` — an operator-facing **HTML dashboard** of currently connected peers
  (`nodes_page.go`): a two-panel layout — a detailed peer table (peer ID, connection
  direction, chosen IP + scope pill, estimated location, remote multiaddrs) beside a
  Leaflet/OpenStreetMap map with a marker per located peer. `nodeGeos` gathers the view
  from `Network().Peers()`/`ConnsToPeer`, preferring a global remote IP over a private
  one for placement and classifying it (`global`/`local`/`unknown`). Positions come from
  an optional [`geoip.Locator`](../geoip/README.md) wired by `SetGeolocator` (nil = off,
  the default — the page then shows a hint to start the node with `-geoip=ip-api`). Only
  global IPs are geolocated; a LAN/loopback peer is marked `local` and never plotted.
  Peer-supplied strings reach the page only through `html/template` escaping (the table)
  or JS `textContent` (the map popups), never as raw HTML. Leaflet + the OSM tiles load
  from public CDNs, so the map needs outbound internet; the list works offline.
- `GET /metrics` — Prometheus text exposition of the same snapshot, including
  `revika_build_info{version,build_date}`, `revika_protocol_info{protocol}` (one line per
  served stream protocol), `revika_bootstrap_info{addr}`,
  `revika_pow_enabled{puzzle}`, `revika_pow_difficulty_bits`, the load gauges
  `revika_capacity_bytes` / `revika_free_bytes` / `revika_load_ratio`, and the maintenance
  gauges `revika_repair_enabled` / `revika_repair_interval_seconds` /
  `revika_rebalance_enabled` / `revika_rebalance_interval_seconds` /
  `revika_rebalance_threshold`.

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
