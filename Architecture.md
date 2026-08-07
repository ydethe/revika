# revika — Architecture

> **Status:** the offline core loop is implemented; the network and everything above the
> pipeline is still target design. This document mixes both — each layer is tagged
> **[implemented]**, **[partial]**, or **[planned]** so the map stays honest. It should
> be kept in sync with the code as more lands. For the condensed version and day-to-day
> guidance, see [CLAUDE.md](CLAUDE.md).
>
> **Implemented today** (`internal/`, all passing `go test -race`): `store` (Mem + Disk),
> `crypto` (AES-256-GCM), `erasure` (Reed–Solomon), `chunk` (fixed-size), `pipeline`
> (`StoreFile`/`LoadFile`), `repair` (`Check`/`Repair`). Built with **Go 1.26**, module
> path **`revika`**, `klauspost/reedsolomon` **v1.14.1**.

## 1. Goal

A decentralized, distributed, end-to-end encrypted storage system — a self-hosted
Dropbox/Drive that runs over a peer-to-peer network instead of a central server. Files
are split, encrypted, and spread across many independent nodes so that no single node
holds a whole file and the system tolerates node loss.

### Roles

- **User** — stores, retrieves, and shares data; holds the encryption keys; interacts
  with the network through the User daemon.
- **Node** — a server that stores encrypted shards on behalf of one or more users.
- A single machine can be both (a User who also contributes storage as a Node).

### Release artifacts

- **`revika-node`** — headless binary for server-only participation (Node role).
- **`revika-daemon`** — a background service (macOS/Windows, OneDrive-style) that syncs
  a local folder to the network, handles retrieval, and *optionally* runs the Node
  service in-process.

## 2. Guiding principle: capability-based, provider-is-untrusted

The design decision everything else follows from: **nodes are dumb, untrusted blob
stores.** They only ever see encrypted, erasure-coded shards addressed by content hash.
All intelligence — chunking, encryption, key management, sharing — lives on the User
side.

Consequences:

- A node is trusted for **availability**, never for **confidentiality** or
  **integrity**. Confidentiality comes from client-side encryption; integrity comes from
  content addressing (a shard's ID *is* its hash, so tampering is self-detecting).
- No node, and no operator of a node, can read user content or enumerate what a user
  stores.
- The network can be fully open/permissionless without weakening privacy.

This trust model runs on modern P2P plumbing (go-libp2p) and content
addressing (IPFS-style provider records).

## 3. Layered architecture

```
┌─────────────────────────────────────────────┐
│ OS filesystem integration (mount)             │  FUSE / File Provider / Cloud Filter [planned]
├─────────────────────────────────────────────┤
│ Sync engine (daemon only)                     │  watch folder ⇄ network        [planned]
├─────────────────────────────────────────────┤
│ Filesystem / metadata layer                   │  dirs, manifests, mutable root [implemented]
├─────────────────────────────────────────────┤
│ Capability & crypto layer                     │  per-object keys, cap chain    [implemented]
├─────────────────────────────────────────────┤
│ Encoding pipeline                             │  chunk → compress → encrypt → erasure  [implemented]
├─────────────────────────────────────────────┤
│ Placement / repair layer                      │  placement [planned] / repair [impl.]
├─────────────────────────────────────────────┤
│ Storage layer (Node)                          │  blob store by shardID      [implemented]
├─────────────────────────────────────────────┤
│ Network layer — go-libp2p                     │  identity, transport, protocols [partial]
└─────────────────────────────────────────────┘
```

Both binaries share a **core library**. The Node binary exercises the bottom layers
(network + storage + repair-serve); the User daemon exercises all of them. Today the
core library exists (`store`/`crypto`/`erasure`/`chunk`/`pipeline`/`repair`) but the
network layer and the two `cmd/` binaries do not.

### 3.1 Network layer — go-libp2p

`github.com/libp2p/go-libp2p` provides:

- **Peer identity** — every participant has a libp2p keypair; the PeerID is the hash of
  its public key. Node identity and (optionally) User network identity are libp2p keys.
- **Secure, multiplexed transport** — authenticated + encrypted channels (Noise/TLS),
  stream multiplexing over TCP and QUIC.
- **Discovery** — Kademlia DHT (`go-libp2p-kad-dht`) on a private `/revika` prefix; DHT-only (no LAN/mDNS path).
- **NAT traversal** — AutoNAT, hole-punching (DCUtR), and relay for peers behind NAT.

Do not roll a bespoke wire protocol. All revika interactions are **libp2p stream
protocols** with versioned protocol IDs (see §6).

**Node self-defence (anti-DoS/DDoS).** A node is *dumb about content*, not defenceless
about its own availability. Operators enable local defences that act only on
connection/identity/volume metadata and never decrypt or interpret a shard, so the trust
model in §2 is untouched. The first three are **[implemented]** in `internal/net/defense.go`
(wired via `HostConfig.Defense` on `libp2p.New` in `host.go`):

- **`ResourceManager` (rcmgr) — [implemented]** — an explicit fixed limiter from
  `rcmgr.DefaultLimits.AutoScale()` (scaled to the host's memory + FD budget) bounding
  memory, streams, and connections per scope so one peer can't exhaust the host.
- **`ConnManager` — [implemented]** — low/high connection watermarks (defaults 64/192) with
  a grace period (30 s), trimming the least-useful connections once the count exceeds the
  high mark. `-conn-low`/`-conn-high`/`-conn-grace` tune it; `-conn-high 0` disables it.
- **`ConnectionGater` — [implemented]** — a **peer-ID / subnet blocklist** (`blocklistGater`)
  consulted on inbound *and* outbound dials, so a known-abusive peer is refused at the transport
  layer before any protocol handler runs. Seeded from `revika-node -blocklist <file>` (one peer
  ID, CIDR, or bare IP per line; `#` comments). The peer set is **runtime-mutable and
  persistent** (`net.Blocklister`): the operator's static entries are unioned with an on-disk
  `blocklist.auto` (`-blocklist-auto`, default `<data>/blocklist.auto`) that the
  maintenance-abuse detector below appends bans to and reloads on restart, so a ban outlives the
  process. A runtime ban also drops the peer's live connection (`Network().ClosePeer`), not just
  its next dial.
- **Maintenance-abuse detection — [implemented]** (`internal/net/abuse.go`, `AbuseMonitor`) — a
  node locally blacklists a peer that abuses the two grant-authorized *maintenance* flows it
  drives against this node (§3.4), acting only on connection/identity metadata. Two triggers:
  (a) **off-schedule rebalancing** — a rebalance move carries a `MoveReason` byte
  (`/revika/shard/1.2.0`), and a peer whose sweeps arrive *too fast* (gap `< interval −
  tolerance`; coalescing a sweep's PUT burst into one event, first event baseline-only) is
  banned on the first violation — too-slow is fine; (b) **possession lies** — a peer that fails
  a fresh-nonce possession proof for a shard it should hold accrues decaying strikes and is
  banned at a threshold (default 3). Its tuning
  (`-rebalance-abuse-tolerance/-coalesce/-strikes/-decay`) is a *local* defence, never inherited
  from bootstrap.
- **Rate limiting — [planned]** — a per-peer and per-owner token bucket on the write verbs
  (`PUT`/`DELETE`), keyed on the Ed25519 owner pubkey the auth token already carries
  (§3.2, `internal/net/auth.go`); anonymous reads (`GET`/`HAS`/`PROBE`) limited per-peer/IP
  only. A new `statusRateLimited` response code surfaces the rejection.

These are *flow/connection* caps that complement the existing *storage* caps (per-owner
quota + leases, §3.2). Ban-by-identity is only as strong as the cost of minting a fresh
identity, so revika makes owner identities **self-certifying** via proof-of-work: a valid
Ed25519 owner key must, on its own, hash under a difficulty target, so it costs
seconds-to-minutes of CPU to mint but one hash to verify — a banned owner cannot re-mint in
milliseconds (`internal/cap/pow.go`; minted by `revika-ctl keygen` and enforced on PUT by a
node via `Server.SetPoW` / `revika-node -pow-difficulty`, **[implemented]**; a client-side
**policy advertisement** so the client learns a node's requirement up front and fails fast —
the `/revika/params` query (`net.QueryParams`), which `revika-ctl connect` reads to mint a
satisfying identity with no PoW flags — is also **[implemented]**). The same advertisement lets
a node **inherit** policy: a node's role is decided purely by whether `-bootstrap` is given.
Only the network's seed node states the cluster policy — admission (`-pow-difficulty`) *and*
maintenance cadence (repair, rebalance; §3.4); a joining node passes only `-bootstrap` and
learns *and* enforces its bootstrap peers' policy via `net.FetchNodePolicy` (which superseded
the PoW-only `FetchPoWPolicy`: PoW strictest-wins, repair/rebalance any-enabled + shortest
interval), so both admission and the maintenance schedule propagate without the operator
re-typing them (**[implemented]**). The puzzle is always the memory-hard
`Argon2idPuzzle`, which collapses the GPU/ASIC advantage over an honest CPU; only the
difficulty varies, so a minter and a verifier never negotiate which puzzle to use. Difficulty
is *local* operator policy, checked statelessly with no authority or consensus. This is a re-mint speed bump keyed to the ban loop, not a
per-identity tax: identity bans still pair with an optional owner allowlist for hardened
deployments (**[planned]**), and global anti-Sybil, reputation, and economic deterrents stay
deferred (§5, §10).

### 3.2 Storage layer (Node) — **[implemented]** (`internal/store`)

A content-addressed blob store. The `Store` interface is content-addressed: `Put`
computes the ID, callers never supply it.

```go
type ShardID [32]byte // sha-256 of the bytes
type Store interface {
    Put(ctx, data []byte) (ShardID, error) // id = sha256(data); idempotent
    Get(ctx, id ShardID) ([]byte, error)   // ErrNotFound / ErrCorrupt
    Has(ctx, id ShardID) (bool, error)
    Delete(ctx, id ShardID) error
}
```

Two implementations pass a shared conformance suite:

- **`MemStore`** — map + `sync.RWMutex`; the development "mock store".
- **`DiskStore`** — files under a root dir, fanned out by ID prefix (`ab/abcdef…`);
  writes go to a temp file and are atomically renamed. On `Get` it re-hashes and returns
  `ErrCorrupt` if the bytes no longer match the ID, so the store is self-verifying.

Node responsibilities still **[planned]**: **leases/expiry** (renewable holds so
abandoned shards are GC'd) and **quotas** (per-node capacity, per-user accounting) — these
arrive with the network layer, since only a networked node needs them. The
**proof-of-possession** probe endpoint (§3.4) is now **[implemented]** (`/revika/probe`).
`.revika/shards/` is the intended on-disk root.

### 3.3 Encoding pipeline (User) — **[implemented]** (`internal/pipeline`, `chunk`, `crypto`, `erasure`)

`StoreFile(ctx, store, cfg, reader) → FileManifest` runs the store path chunk by chunk;
`LoadFile(ctx, store, manifest, writer)` runs it in reverse. `Config` is
`{ChunkSize int; Params erasure.Params; Compress bool}` (default 4 MiB chunks, `k=4`,
`m=2`, compression on).

1. **Chunk** (`internal/chunk`) — **fixed-size** for now, exposed as a Go
   `iter.Seq2[[]byte, error]`. Content-defined chunking (FastCDC-style rolling hash, so
   an edit only rewrites the affected chunk) is a **[planned]** upgrade behind the same
   iterator contract.
2. **Compress** (`internal/compress`) — **optional**, gated by `Config.Compress`. Each
   chunk is DEFLATEd (stdlib `compress/flate`) *before* encryption, since ciphertext is
   incompressible. The compressed form is kept only when it is actually smaller, so
   incompressible data is stored verbatim; the per-chunk outcome is recorded in
   `ChunkRef.Compressed` and drives decompression on load. (Note: compress-then-encrypt
   leaks plaintext length — a CRIME/BREACH-class trade-off accepted for at-rest storage.)
3. **Encrypt** (`internal/crypto`) — each chunk gets a fresh random key and is sealed
   with **AES-256-GCM** (stdlib `crypto/aes`+`crypto/cipher`; 12-byte random nonce
   prepended). AES-GCM was chosen over XChaCha20-Poly1305 to avoid an external
   dependency; it is isolated behind `Seal`/`Open` and swappable. Per-object random keys
   avoid the equality-leak of convergent encryption.
4. **Erasure-code** (`internal/erasure`) — Reed–Solomon (`klauspost/reedsolomon`) splits
   the *encrypted* chunk into `k` data + `m` parity shards; any `k` of the `k+m`
   reconstruct it. An 8-byte length header is prepended so `Decode` recovers the exact
   original length despite RS zero-padding. **`Encode` is deterministic** — the same
   input always yields byte-identical shards (this is what makes repair address-stable,
   §3.4).
5. **Address & store** — each shard is `Put` into the `Store`; its `shardID = hash(shard)`
   is recorded in the chunk's `ChunkRef`.

Retrieval fetches whatever shards are available (missing/corrupt ones are tolerated up
to the erasure margin) → erasure-decode → decrypt → decompress → reassemble.

### 3.4 Placement / repair layer

**Placement — [partial]** (`internal/net`, `PlacementStore`). Shards are spread across
`n = k + m` nodes discovered on the DHT: a first-cut **round-robin** policy sends a
chunk's consecutive shards to distinct nodes, so no single node holds enough of a file to
matter (the `revika-ctl cp` DHT path, bootstrapped from the workspace). Each holding node announces a
**provider record** to the DHT (`shardID → {peers holding it}`) on receipt, keyed by a
CIDv1(raw codec) wrapping the shard's SHA-256; a client's `cp` (retrieve) resolves those records to
fetch shards it has no prior knowledge of. Still **[planned]**: richer node selection —
*diversity* (independent operator/network domains so correlated failures don't drop below
`k`), *reliability* (uptime/reputation), *proximity/cost* — and graduating the policy from
`internal/net` into a dedicated `internal/placement`.

**Repair — [implemented]** (`internal/repair`), against the mock/local store.
`Check(ctx, store, manifest)` probes shard availability per chunk (via `Store.Has`) and
returns a `Report`; `Repair(ctx, store, manifest)` regenerates missing shards for every
chunk that is still recoverable (≥ `k` shards present), restoring full redundancy.
Chunks that have dropped below `k` are reported as unrecoverable via a joined error
without disturbing the others.

Two properties make repair clean, and both are exploited by the implementation:

- **It needs no decryption key.** Repair works entirely on ciphertext shards — it
  erasure-decodes `k` survivors to recover the *encrypted* payload, never the plaintext.
  (In capability terms it needs only a verify-cap, §3.5.)
- **Regenerated shards keep their content address.** Because `erasure.Encode` is
  deterministic, re-encoding the recovered payload reproduces byte-identical shards, so a
  regenerated shard has the *same* `shardID` — the manifest never needs rewriting. The
  code asserts `Put` returns the expected ID as a guard against accidental
  non-determinism.

The network-side **proof-of-possession** probe (a remote node proves it holds a shard
without shipping it — `/revika/probe`, `NetStore.Probe`/`handleProbe`) is **[implemented]**
and now gates the rebalancer's make-before-break release (§3.4). Still **[planned]** for
*repair* specifically: adopting that probe in the repair loop's availability check (which
still uses `Has`), placing regenerated shards on *fresh* nodes rather than back into the same
store, and the repair *cadence*/threshold policy (who runs it, how often, what margin triggers
it).

**Rebalancing — [implemented]** (`internal/placement.OffloadBytes` + `internal/store.DiskUsage`
+ `internal/net/{balance,rebalance}.go`, protocol `/revika/balance/1.0.0`, driven by
`revika-node`'s `rebalanceLoop`). Placement decides where a *new* shard lands; rebalancing
corrects the *standing* distribution as nodes join, leave, fill up, or differ in capacity. It
is distinct from repair: repair restores lost redundancy and only ever *adds* a shard onto a
fresh node (`RepairStore.Put`), so on its own it lets early and small nodes saturate while
later/larger nodes stay empty. The target is that, asymptotically, every node carries the
same **fraction of its own capacity** — not the same absolute shard count.

- **Model — normalized load, not shard count.** Balancing by count is wrong under
  heterogeneity: a Raspberry Pi and a cloud server should not hold the same number of shards.
  Each node's load is `L_i = used_i / capacity_i ∈ [0,1]` (`placement.Load.Frac`), with
  `capacity_i = min(free-disk, operator budget)`; the network converges `L`, not counts.
  Because chunking is fixed-size (§3.3) a shard is ~constant-size, so "same fraction of
  capacity" and "count proportional to capacity" coincide once normalized. The capacity signal
  is now sensed end-to-end: a node samples free/total disk on its shard dir
  (`store.DiskUsage` → `syscall.Statfs`, with a portable stub returning `ErrUnsupported`),
  the node's `LoadSource` closure folds that with the ledger's `bytes_used` and the
  operator `-capacity` budget into a `LoadReport`, and this is exposed on the `/status` +
  `/metrics` surface (`StorageInfo.{CapacityBytes,FreeBytes,Load}` + the
  `revika_capacity_bytes`/`revika_free_bytes`/`revika_load_ratio` gauges) and gossiped (below).
  *Still deferred:* feeding this back into `placement.Node.{Free,Weight,Domain}` /
  `WeightByFree` / `Spread` at *placement* time — the rebalancer computes moves directly from
  normalized load and the ledger, and does not yet enforce the failure-**domain** `Spread`
  invariant on a move.
- **Mechanism — pairwise diffusion (dimension-exchange).** Rather than compute a global
  average and chase an absolute target, each node runs a periodic, jittered round
  (`Rebalancer.RunOnce`): sample a few storage peers (`Discovery.FindNodes`), query normalized
  load over `/revika/balance` (`QueryLoad`), pick the emptiest sampled peer (*power-of-k
  choices*), and push cold shards toward it. `placement.OffloadBytes` is the pure decision
  function — how many bytes to shed to close half the load gap. Pairwise load diffusion
  provably converges to uniform load on a connected graph with no coordinator or global view,
  and maps cleanly onto libp2p gossip. It converges to *within* the threshold band below, which
  is the point.
- **Thrashing control — threshold + hysteresis + cooldown + jitter.** Node A offloads to B
  only when `L_A − L_B > θ` (a dead-band, default `0.10` = 10 percentage points, the
  `-rebalance-threshold` flag), and then moves only enough to close *half* the gap before
  stopping. The dead-band makes the system settle "to within θ" instead of chasing the last
  shard, killing the ping-pong by construction. Three guards back it: a per-shard **cooldown**
  (a just-moved shard is pinned for `2×` the rebalance interval so it can't bounce A→B→A — an
  in-memory map on the `Rebalancer` today, not yet ledger-persisted across restarts),
  **jitter** on the rebalance tick (via the same `sleepJitter` `reprovideLoop`/`repairLoop`
  use) to avoid synchronized herds, and the recipient's **quota** check (B rejects with
  `statusQuotaExceeded` if the shard would push it over, which the mover treats as "peer full"
  and stops shedding to it) so rebalancing never violates the per-owner storage cap (§3.2).
  Which shards move: coldest-first — `ledger.ColdShards` returns the least-recently-stored
  shards first — to minimize disruption.
- **Concentration cap — one node holds at most `m` shards of a stripe.** Before shedding a
  shard, the mover counts (over `/revika/shard` `Has`) how many of that stripe's siblings the
  target already holds and **skips the move** if it would push a single node past `m` shards of
  the stripe (`Rebalancer.peerStripeLoad`). Past `m`, that one node's loss alone drops the
  stripe below `k` and makes it unrecoverable — exactly the leverage a shard-absorbing node
  seeks during diffusion. This bounds *node-level* correlated loss; the stricter failure-**domain**
  `Spread` invariant (no two shards of a stripe in one domain) is still deferred with the
  `Node.Domain` wiring above. Best-effort against a lying `Has`, but the release gate below is
  the hard backstop.
- **Addressing — make-before-break re-provide.** Moving a shard must not lose it. revika is
  spared the usual pain because **location is a DHT provider record, not a hash-into-a-ring**:
  a shard is found because its holder *announces* the CID (`Discovery.Announce`/`FindProviders`,
  §6), an explicit indirection, so relocating a shard is just *changing who announces it*. The
  move is copy-then-drop with a grace window:
  1. A streams the shard to B over the existing grant-authorized `PUT`
     (`NetStore.putGrant`, the same call repair uses), replaying the stripe descriptor and the
     repair grant recorded at store time — so A moves the shard without ever holding the User's
     signing key.
  2. B re-hashes it — shards are content-addressed and self-verifying (§3.2), so B never trusts
     A — then records ownership/lease/stripe in **its** ledger (charged to the shard's original
     owner, whose Ed25519 key travels in the repair grant) and calls `Discovery.Announce` for
     the new provider record.
  3. Only after B **proves possession** does A release its copy. A `PUT`-ack means B echoed the
     content hash *once*, not that it kept the bytes — so A then issues a fresh-nonce
     proof-of-possession `Probe` over `/revika/probe` (`Rebalancer.confirmStored`) and calls
     `Rebalancer.release` — drop A's owner claim (`ledger.DropRecord`, crediting the quota back)
     and delete the local blob — *only when B passes*. A peer that absorbs the shard and drops it
     fails the probe, so A keeps its only durable copy (a proof *mismatch* also halts shedding to
     that peer for the round; a probe transport error just retains the shard). This wires the
     `/revika/probe` primitive — previously repair-only — into the write path. Once released,
     A's ~12 h reprovide / ~24 h record TTL means A's stale provider record lingers harmlessly
     during DHT propagation, so the shard is announced by both for a window (never neither).

  Even a transient stale record is covered by erasure coding, since `DHTStore.Get` already maps
  a provider miss to one lost shard, reconstructible from any `k`. This is the
  repair-onto-fresh-node primitive plus the *source-side drop* that turns a *copy* into a
  *move* — so rebalancing lands as an extension of repair, not a new subsystem.
- **Trust.** Gossiped load is a *declared* value: a node can lie about `L` to attract or shed
  shards. Content is safe regardless (shards stay self-verifying ciphertext), and durability is
  now protected against the classic grief — a node that declares itself empty, absorbs shards,
  then deletes them — by two mechanism-level guards that do **not** depend on identity (so they
  hold even against Sybils): the concentration cap bounds how much of one stripe any single node
  can attract, and the proof-gated release means the mover never drops its copy for a peer that
  can't prove possession. A liar can still distort *placement* (waste move rounds, skew load).
  Locally, a node now also *penalises* the two abuse signals it can observe first-hand (§3.1,
  `AbuseMonitor`): a peer that racks up possession-lie strikes (repeated fresh-nonce probe
  failures) or rebalances against this node *off-schedule* (`ReasonRebalance` PUTs arriving
  faster than the cluster interval allows) is added to this node's persistent blocklist. That is
  a per-node reflex on connection/identity metadata, not consensus; binding declared load to a
  *network-wide* reputation/anti-Sybil layer — so a proven liar is penalised everywhere, not
  just where it was caught — is deferred with the rest of the economic layer (§5, §10).

### 3.5 Capability & crypto layer — **[partial]** (`internal/crypto`, `internal/cap`)

**Implemented:** symmetric authenticated encryption — `NewKey`, `Seal`, `Open`
(AES-256-GCM, `internal/crypto`), used by the pipeline for per-chunk encryption; and a
first cut of **cap delivery** (`internal/cap`): ML-KEM-768 recipient identities
(NIST FIPS 203, `crypto/mlkem`) with `Wrap`/`Unwrap` (a KEM-DEM: ML-KEM encapsulation
keying an AES-256-GCM seal), which `revika-ctl share rvk:<path>` uses to encrypt a
read-cap to a recipient's public key. `share` resolves the path in the User's
namespace and seals the `ReadCap` of the file or subdirectory there (§3.6), so you
can hand over one file (or one subtree) from a larger stored tree without
re-uploading it and without exposing anything outside the shared path — a directory
cap grants exactly its subtree and everything reachable from it, no more. Concretely
`share` wraps a `RootPointer` anchored at that subtree, signed by the sharer and
sealed to the recipient's key: a **sealed shared root** the recipient opens with
their private key and uses as their `-root`, browsing it with `ls` and
reconstructing files with `cp` (which auto-detect file vs. subtree from the cap's
`Kind`). The derivation chain (write-cap → read-cap → verify-cap) is
**[implemented]** in `internal/manifest` (`WriteCap` alias, `ReadCap.VerifyCap()`,
`VerifyCap.ReadCap()`); **still planned** is a compact string form for caps.

The **capability** ("cap") is how access is named and delegated:

- A **read-capability** = *manifest location* + *decryption key(s)*. Whoever holds it can
  read the object. Nothing else is needed, and nodes never see it.
- A **write-capability** for mutable objects = a signing private key; possession lets you
  publish new versions.
- Derivation chain: **write-cap → read-cap → verify-cap** — **[implemented]**
  (`internal/manifest`). Each level derives from the one above but not below, so you can
  hand out exactly the privilege you intend:
  - write-cap (`WriteCap` = the Ed25519 `cap.SignKey`): full read/write — the sole authority
    to sign a new `RootPointer`,
  - read-cap (`ReadCap`): read only — the per-blob AES key plus its shard content addresses,
  - verify-cap (`VerifyCap = ReadCap.VerifyCap()`): the read-cap minus its AES key — locates
    and integrity-checks a blob's shards (`manifest.VerifyBlob`) without decryption rights, so
    a repairer or the public DHT record can carry it. `VerifyCap.ReadCap()` re-embeds a zero
    key, making the downgrade one-way. A `RootPointer` signs over the *verify projection* of
    its cap, so the identical signature validates both the local full-key pointer and the
    key-stripped one published to the DHT.

**Key material:**

- per-chunk/per-object symmetric keys (random),
- per-User asymmetric identity keys (ML-KEM-768 for cap delivery, Ed25519 for signing root
  pointers) — kept in `.revika/keys/`,
- libp2p peer keys for network identity.

Cap wrapping uses the stdlib `crypto/mlkem` (ML-KEM-768, FIPS 203) keying an AES-256-GCM
DEM. For the remaining planned pieces, use `hkdf` for key derivation and stdlib
`crypto/ed25519` for signatures. (Both chunk encryption and the cap DEM use stdlib
AES-256-GCM, and the KEM is stdlib too, so no direct `x/crypto` dependency exists.)

#### Why not proxy re-encryption (PRE / IB-CPRE) for sharing? — **[rejected for v1]**

A recurring suggestion is to share via **proxy re-encryption** — and specifically
**identity-based conditional proxy re-encryption (IB-CPRE)** — instead of wrapping and
handing over a read-cap. In a PRE scheme the owner gives a *re-encryption key* to a proxy
(here, a node); the proxy transforms ciphertext-under-Alice into ciphertext-under-Bob
without learning the plaintext, Bob decrypts with his own key, and the *conditional*
variant scopes a re-encryption key to ciphertexts matching a tag/condition while the
*identity-based* variant lets you re-encrypt to an identity string rather than a fetched
public key. It is an appealing model, but it fights three of revika's settled constraints,
so it is **not adopted for v1**.

First, a **layering** point that decides where PRE could even sit. Shard bytes are
*already* AES-256-GCM ciphertext under a per-chunk random key, and *then* erasure-coded
(§3.3). The confidentiality boundary is the small set of per-chunk keys — the thing worth
sharing is the ~tens-of-bytes read-cap/manifest, not the megabyte shards. So there are two
very different places PRE could apply, and "re-encrypt the shards" is the one that breaks
the most:

1. **Shard-level PRE breaks content addressing and repair.** `shardID = hash(shard)`
   (§3.2). If a node re-encrypts a shard for a recipient, the output is different bytes →
   different hash → the manifest's shard IDs no longer resolve, dedup dies, and **repair
   breaks**: repair depends on `erasure.Encode` being deterministic so regenerated shards
   reproduce their content address and the manifest never changes (§3.4). Recipient-specific
   ciphertext destroys that invariant. It also turns a node from a *dumb, untrusted blob
   store* (§2) into an active crypto participant holding re-encryption keys, and
   proxy-plus-recipient collusion is a live concern in several PRE schemes — a real
   departure from revika's trust model.

2. **The "identity-based" part needs a trusted authority.** IBE-family schemes require a
   **Private Key Generator** that can derive *any* user's private key — inherent key escrow
   via a central authority. That directly contradicts revika's *no central server* goal
   (§1), independent of the crypto involved.

3. **PQC rules it out today regardless.** revika's settled constraint is that *all crypto
   must be PQC-class*. Essentially every mature, analyzed PRE / IB-PRE / conditional-PRE
   scheme is **pairing-based** (bilinear maps) and only classically secure. Lattice-based
   PRE (LWE/NTRU) exists in the literature but is research-grade: no FIPS standard, not in
   the Go stdlib, large ciphertexts, and noise growth that bounds the number of
   re-encryption hops. Adopting it means an experimental external crypto dependency or
   hand-rolling — against both the PQC requirement and the deliberate stdlib/FIPS stance
   that gave us ML-KEM-768 (FIPS 203) and Ed25519.

The idea does point at a **genuine weakness** in the current model: a read-cap hands over
raw chunk keys, which is *coarse* (whole-manifest granularity) and *irrevocable* (once a
recipient has the keys, they can never be taken back). The valuable properties PRE offers —
delegation without disclosing the master key, conditions, and revocation — are better
obtained here at the **cap layer**, PQC-safely and without a proxy or a PKG:

- **Revocation** via re-keying + CoW — **[implemented]** (`manifest.Rekey`,
  `pipeline.ReencryptFile`, `revika-ctl revoke`): re-encrypt every blob at and below the
  shared subtree down to the data chunks under fresh keys, mint fresh caps, CoW-graft a new
  root, advance the `RootPointer` `Seq`, and republish; the old (shared) cap then names only
  orphaned shards, which are reclaimed. Honest limit: this denies *future* reads only — bytes
  and keys a recipient already downloaded cannot be clawed back.
- **Conditions / least privilege** via the existing **write-cap → read-cap → verify-cap**
  derivation chain (§3.5): mint narrow read-caps per subtree instead of one master cap.
- **Delivery** stays the ML-KEM-768 `Wrap`/`Unwrap` already implemented.

PRE is therefore **parked**, not pursued: revisit only if a standardized, stdlib-grade
lattice PRE appears *and* a variant exists that avoids a trusted PKG and can operate at the
cap layer rather than on content-addressed shards. Tracked in §10.

### 3.6 Filesystem / metadata layer — **[partial]**

- **File manifest** — **[partial]**. `pipeline.FileManifest` exists today as an in-memory
  value: the original file name, ordered `ChunkRef`s (per-chunk key + ordered shard IDs),
  the `Config`, total size, and a `Metadata` record. The name lets `get` restore the file
  under its original name without being told it; the metadata makes the manifest
  **mount-ready** (§3.8). `Metadata` carries the POSIX/stat attributes and the cross-platform
  fields the native cloud-provider frameworks require — `Mode`, `Uid`/`Gid`, the four times
  (`ModTime`/`ChangeTime`/`AccessTime`/`BirthTime`, all ns), attribute `Flags`
  (hidden/read-only/system/archive), `ContentType`, `SymlinkTarget`, extended attributes
  (`Xattr`), and deterministic `ContentVersion`/`MetaVersion` change tokens
  (`pipeline.DeriveVersions`) matching File Provider's `NSFileProviderItemVersion` and Cloud
  Filter's drift detection. The stable *item identifier* (FP `itemIdentifier` / CF
  `FileIdentity`) is intentionally left to the directory manifest, being a namespace concern,
  not a content property. `revika-ctl` captures metadata on `put` (portable subset everywhere;
  uid/gid/atime/ctime/xattrs on Linux via `meta_linux.go`) and restores it on `get`
  (chmod/chtimes/chown/setxattr, plus symlink recreation), serializing it as manifest **v4**
  (`meta` object; v1–v3 still decode with zero metadata). Encrypting the manifest and storing
  it as an immutable blob whose read-cap is the file's read-cap is **[implemented]**
  (`internal/manifest`, below). Still **[planned]**: richer per-OS capture (darwin/windows
  uid/gid/btime/xattr, arriving with the native bindings), and moving the metadata type into
  `internal/manifest`.
- **Cap-addressed blob layer** — **[implemented]** (`internal/manifest`). The manifest is now
  storable as an immutable, encrypted, content-addressed **blob**: `pipeline.StoreBlob`/`LoadBlob`
  run a single serialized object through the same compress → encrypt → erasure → store path as
  file data, and the result is named by a **`ReadCap`** — a per-blob AES-256 key + the ordered
  content addresses of its shards, tagged with a `Kind` (file/dir). A `ReadCap` *is* the file's
  read-capability, and because it carries content-addressed shard IDs it commits to the blob's
  exact bytes.
- **Directory** — **[implemented]** (`internal/manifest`, `DirManifest`). An encrypted map of
  names → child caps (files or subdirectories), itself stored as a `KindDir` blob. Since a
  directory's cap commits to its children's caps, a directory tree is a **Merkle DAG of encrypted
  blobs**: `Resolve` walks a path from a root cap; `Graft`/`GraftRemove` mutate **copy-on-write**
  (rewrite only the path from the changed node to the root, sharing every untouched sibling
  subtree). Names live in the directory `Entry`, not in the (nameless, content-addressed) file
  blob, so a rename rewrites one directory blob and never re-addresses the file. Each `Entry`
  carries a small `StatCache` (kind/size/mode/mtime/version tokens) so a mount serves
  `readdir`/`getattr` without hydrating the child (§3.8). `revika-ctl cp` stores a file or a
  whole filesystem directory as such a tree, grafting it into the User's namespace under an
  `rvk:` path, and retrieves either back (`cmd/revika-ctl/tree.go`), exercised in-process
  (`tree_test.go`, `namespace_e2e_test.go`) and over a live
  multi-node network (`deploy/tree.sh`, compose profile `tree`). Because `Resolve` yields a
child's `ReadCap` and a cap is shareable on its own, `revika-ctl share rvk:<subpath>` wraps
just one file's or subdirectory's cap out of the namespace (§3.5) — the recipient
reconstructs exactly that file or subtree and nothing outside the shared path. Still
**[planned]**: HAMT/B-tree
  sharding for very large directories (a blob is one erasure chunk today — see the size budget in
  `internal/manifest/README.md`).
- **Root pointer** — **[partial]** (`internal/manifest`, `RootPointer`; persisted by
  `provider.FileRootStore`). The one mutable anchor per User (see §4): a signed
  `owner-pubkey → root-directory cap` record with a monotonic sequence, `SignRoot`/`Verify` over
  a domain-separated Ed25519 payload. The type + anti-rollback semantics exist and are now
  **realized in the CLI**: `revika-ctl` persists the pointer to a local `root.json` inside a
  *workspace* folder (`-root`/`$REVIKA_ROOT`, default `.revika`) and advances its `Seq` on every
  `cp`/`rm` mutation. The workspace, created by `revika-ctl connect` (`cmd/revika-ctl/config.go`),
  also holds a `config.json` recording how to reach the network (bootstrap peers), the erasure
  rate (`k`/`m`), and the node's proof-of-work admission policy, plus the User's keys under
  `keys/` — so a command needs only `-root <folder>` and mints its identity lazily on first write.
  A *shared* root is that same pointer anchored at a shared subtree and sealed to a recipient's
  ML-KEM key (passed as a bare `-root <file>`, outside any workspace). **[planned]** is
  publishing/fetching the pointer over the DHT and the
  `/revika/root` protocol, which would let a shared root be resolved network-wide instead of
  travelling as a file.

These three types are exactly what the mount layer (§3.8) resolves against: the file manifest
plays the role of an inode, the directory the namespace, and the root pointer the mutable
superblock.

### 3.7 Sync engine (daemon only) — **[planned]**

OneDrive-style: watch a local folder (`fsnotify`), diff against the last-known state,
and reconcile:

- local change → run the store pipeline, update manifests/directory, publish new root;
- remote change (newer root observed) → fetch and materialize into the local folder;
- conflicts → resolved by sequence number + a conflict-copy fallback (never silently lose
  data).

#### 3.7.1 Multi-device write reconciliation (inline) — **[implemented]**

Several devices of one User share the **same** Ed25519 owner signing key — that is the only
way to advance the root. Concurrent commits from two devices at the same `Seq` would otherwise
silently lose one side (the DHT has no compare-and-swap). The client resolves this **inline on
every `cp`/`rm`/`revoke`**, without needing the (still-planned) sync daemon:

- **Read-merge-publish loop** (`cmd/revika-ctl` `commitRoot`). Before publishing, the client
  reads the current DHT root. If it diverged from this device's *merge base* (a local, unsigned
  sidecar `<workspace>/base.json` recording the last root this device reconciled), the client
  three-way-merges the two roots, signs at `max(local, remote).Seq + 1`, publishes, and re-reads
  to catch a racing writer — folding and retrying if one won. The durable local `root.json`
  stays authoritative; a DHT failure never fails the commit.
- **Merge primitive** (`manifest.Merge3`). Recursive over the COW Merkle DAG with cap-equality
  pruning: an unchanged subtree keeps an identical cap on both sides and is taken whole. Only a
  genuinely divergent directory is descended. A leaf both sides changed differently is never
  dropped — the local edit keeps its name and the remote edit is filed as a **conflict copy**
  (device-tagged, e.g. `report (conflict a1b2).pdf`); a delete racing an edit keeps the edit.
- **Read-key delivery — the sealed self-root companion.** Per-blob AES keys are random per
  write and the public DHT root is *key-stripped* (verify projection), so a second device learns
  shard locations from the public root but **cannot decrypt or merge** another device's content.
  Alongside the verify-root, each commit therefore publishes a companion record
  (`manifest.FullRootRecord`) under `/revika-fullcap/<owner>`: the **full** root cap (with its
  AES key) sealed to the owner's own ML-KEM-768 public key (`manifest.WrapCap`). Every device
  holds the shared owner ML-KEM private key, so every device can open it; the public DHT still
  never carries a decryption key. A reader binds the companion to the signed verify-root
  (`companion.VerifyCap() == verifyRoot.Root`), tying the decryptable cap to the authentic,
  monotonic `Seq` without a second signature.
- **Convergence & residual.** `Seq` is monotonic and `Merge3` is content-complete, so published
  roots form a rising, eventually-agreeing chain; divergent writes surface as conflict copies,
  never silent loss. Because a DHT has no CAS, the read→publish window cannot be fully closed —
  the re-read+retry narrows it. Worst case (an equal-`Seq` fork whose `rootValidator.Select`
  loser never writes again): its change stays in its local `root.json`/base until its next write
  re-enters the loop and folds it in. Closing that permanently needs the background sync daemon
  (§3.7), still out of scope. Both DHT records (verify-root + companion) refresh on each write
  and share the DHT record lifetime; a device that never writes again lets them expire like any
  other stale namespace state.

### 3.8 OS filesystem integration (mount layer) — **[planned]**

Where the sync engine (§3.7) mirrors the network into a *plain local folder*, the mount layer
exposes revika *directly as a mounted filesystem* with on-demand hydration — the model
Dropbox/OneDrive/Google Drive use for "files on demand". The two are complementary surfaces on
the same metadata layer (§3.6), not alternatives; the daemon can offer either.

**There is no single international standard for filesystem integration** — it is three families,
and revika targets them in order:

1. **POSIX / VFS semantics** — the abstract contract (`open`/`read`/`stat`/`readdir`/`write`)
   every backend must honour. Not an integration API; the conformance reference.
2. **FUSE — the cross-platform de-facto standard, and revika's first target.**
   Filesystem-in-userspace: revika implements the VFS callbacks in-process and the OS mounts a
   mountpoint. Linux `libfuse` (kernel-native), macOS **macFUSE**, Windows **WinFsp**
   (FUSE-API-compatible). Fastest path to a working mount from one Go codebase (`internal/mount`,
   pure-Go via `hanwen/go-fuse`). Exposes a classic mountpoint, *not* the placeholder/sync-badge
   UX. Note Apple is progressively locking down kernel extensions, so macFUSE is a PoC vehicle,
   not the long-term macOS surface.
3. **Native "cloud provider" frameworks — the production surface, per-OS.** macOS
   `FileProvider.framework` (`NSFileProviderReplicatedExtension`), Windows **Cloud Filter API**
   (`cldapi.dll` / Sync Root, "Files On-Demand"), Linux GIO/GVfs or KIO. These give placeholder
   files, on-demand hydration, eviction to reclaim space, and status badges in the file manager.
   Not pure Go and not portable — a per-OS binding layer, deferred behind the FUSE PoC.

**The manifest is the inode.** revika's per-file `FileManifest` (§3.6) already carries everything
an inode needs — size, name, and the recipe (per-chunk keys + ordered shard IDs) to produce
content — so "one manifest per file" is not a mismatch with a filesystem, it *is* the resolution
target:

| VFS op | Served from |
|---|---|
| `getattr` / `stat` | manifest `Size` + metadata (mode/mtime — to add) |
| `readdir` | directory manifest (§3.6): names → child caps |
| `open` + `read` | `pipeline.LoadFile` — fetch `k` shards → decode → decrypt |
| `write` + `close` | `pipeline.StoreFile` → new manifest (COW, below) |

**On-demand hydration.** The mount holds only the (tiny) manifest tree locally as *placeholders*;
the network is untouched by `readdir`/`stat`. Only `open`/`read` triggers `LoadFile` to fetch
shards. A file is never materialized whole before it is requested — the natural fit for
erasure-coded, no-node-holds-a-whole-file storage (§2).

**CLI stepping stone — `ls` / `cp` [implemented].** Ahead of the mount, `revika-ctl` exposes the
two-phase model directly over the namespace: `ls rvk:<path>` walks the directory DAG fetching
**only directory blobs** (a listing touches no file content — the `readdir`/`stat` half), and
`cp rvk:<path> <local>` then pulls content for just the chosen file or subtree, fetching only
those files' shards (the `open`/`read` half, driven explicitly instead of by a page fault). An
earlier `sync`/`hydrate` design materialized symlink+empty-file *placeholders* backed by a local
`.revika-sync.json` cap index; that was dropped in favour of listing the live namespace on demand,
since the signed `RootPointer` (persisted in `root.json`) already is the durable anchor and needs
no separate placeholder index. Both `root.json` and any sealed shared root hold read-capabilities
(decryption keys), so they are written `0600` — as secret as a manifest.

**Copy-on-write against immutable content.** Shards and manifests are immutable
(content-addressed, §3.2/§4), yet a filesystem does random writes and renames. So a write
rewrites the affected chunk(s) → a new file manifest → a new parent directory manifest → … → a
**new root**, and the signed **root pointer** (§4) is advanced to it. This is COW up the Merkle
tree: free versioning, a single mutable anchor, and every version signed so a node cannot serve a
rolled-back root. Content-defined chunking (§3.3) matters here so an in-place edit rewrites one
chunk, not the whole file.

**Framework-neutral API — `internal/provider` [implemented].** The three native families above
speak different dialects but require the *same shape*: a rename-stable item identity, a
content/metadata version pair, container enumeration with a delta cursor, on-demand fetch
(hydration) and eviction, and create/modify/delete/rename mutations. `internal/provider` expresses
that union once in Go as the `Provider` interface, so a single core serves all of them and a
per-OS binding layer (the not-pure-Go shim) only has to translate native callbacks into these
method calls. Its default implementation, `provider.Manifest`, resolves every call against the
cap-addressed Merkle DAG (§3.6) over any `store.Store`: reads load directory/manifest blobs
(enumeration touches no content), fetch runs `pipeline.LoadFile`, and each mutation is the
copy-on-write `Graft` above, advancing the signed root pointer (§4). Two pieces are owned here
that the DAG does not yet provide: **stable `ItemID`s** (the frameworks demand identifiers that
survive rename/move; the provider, sole mutator of its domain, keeps an authoritative path⇄ID map
— a future `Entry.ID`, §3.6, could make this intrinsic) and **change enumeration** (diffing two
root caps, pruning unchanged subtrees by cap equality). The one un-networked seam — publishing the
signed root pointer — is isolated behind a `RootStore` interface with a durable local
`FileRootStore`, a DHT-backed `DHTRootStore` (§4), and a `MultiRootStore` that commits the
primary then mirrors best-effort to the DHT. Live-file attribute capture/restore for this and
for `revika-ctl` is shared in `internal/fsmeta`.

This layer is **daemon-only** (`revika-daemon`, §1) and sits on top of the metadata layer; it adds
no new trust assumptions — all chunking, encryption, and erasure coding still happen client-side
before any shard moves (§2).

## 4. Mutable state without global consensus — **[implemented]**

Distributed *mutable* state is the hardest part. **Do not use a blockchain** — it is
overkill for this workload and for a PoC. The immutable half is built
(`internal/manifest` stores chunks, file manifests, and directories as
content-addressed encrypted blobs with copy-on-write mutation), and the one mutable
pointer is now *published* over the network: a DHT value record keyed by the owner
pubkey (`internal/net/root.go`, validated by `rootValidator`) plus a node-served
`/revika/root/1.0.0` stream protocol (`root_proto.go`).

Design:

- Everything content-addressed (chunks, manifests, directories) is **immutable** and
  freely cacheable/dedup-able. **[implemented]** in `internal/manifest`: a `ReadCap`
  (per-blob key + content-addressed shard IDs) names each blob; a directory cap commits
  to its children's caps, so the tree is a Merkle DAG (§3.6).
- The only mutable thing is a small, per-User **root pointer**: a signed record mapping
  `user-signing-pubkey → latest-root-directory cap`, carrying a **monotonic sequence
  number** and timestamp. **[implemented]** as `manifest.RootPointer` (`SignRoot`/`Verify`,
  Ed25519, domain-separated), signed over the cap's *verify projection* so one signature
  validates both the local full-key pointer and the key-stripped DHT record.
- Publish it IPNS-style — **[implemented]**: stored on the DHT keyed by the owner pubkey
  (`Discovery.PutRoot`/`GetRoot`, `rootValidator` enforcing owner-binding + signature and
  selecting the highest `Seq`), and/or fetched directly from a node over `/revika/root/1.0.0`
  (`QueryRoot`). Records expire after the DHT's 48h max age, so a 12h `RepublishRootLoop`
  keeps a live namespace resolvable. `revika-ctl` publishes on every `cp`/`rm`/`revoke`
  commit (best-effort mirror behind the durable local `root.json`, via
  `provider.MultiRootStore` + `DHTRootStore`) and resolves a published root by
  `ls -owner <pubkey-file>` (the signing pubkey is read from a file, never a literal). Because the DHT record carries only a verify-cap, `-owner` resolution
  is an integrity/liveness inspector (detecting revocation), not a decryption path. Readers
  verify the signature and take the highest sequence number.
- Conflict resolution is single-writer-per-key by construction (only the holder of the
  signing key can advance the sequence); multiple **devices** of the same User share that one
  key and reconcile inline on every commit — read-merge-publish against the DHT root, three-way
  `manifest.Merge3` with device-tagged conflict copies, and a sealed self-root companion that
  delivers the decryptable remote root between the owner's own devices (§3.7.1). `Select` breaks
  an equal-`Seq` fork by a total byte-order (not first-seen), so every replica converges on the
  same visible tip and the loser folds its change in on its next write.

**This per-User signed index is what `.revika/`'s "ledger" refers to** — a private
index/accounting of the user's own data and where it lives, *not* a global shared ledger.

## 5. Trust, threat model, and integrity

- **Confidentiality:** client-side AEAD; nodes hold only ciphertext shards. *(Chunk
  encryption implemented; the key-management/capability layer that governs who holds keys
  is planned.)*
- **Integrity:** content addressing makes every shard self-verifying; a modified shard
  fails its hash check and is treated as missing (→ repair). *(Implemented end-to-end:
  `DiskStore.Get` returns `ErrCorrupt`, and the pipeline/repair paths treat corrupt as
  missing.)*
- **Availability:** erasure coding + active repair are implemented against a single local
  store; **diverse placement across nodes is planned**. `k`/`m` and the redundancy margin
  are chosen for target durability. A node also protects *its own* availability with local
  anti-DoS/DDoS defences — `ResourceManager`/`ConnManager` limits and a `ConnectionGater`
  blocklist (§3.1) — that act on connection/identity metadata only, never on shard content.
  The blocklist is runtime-mutable and persistent, and a `net.AbuseMonitor` extends it
  automatically when a peer abuses a maintenance flow (off-schedule rebalancing or repeated
  possession lies — §3.1/§3.4). *(Implemented in `internal/net/defense.go` + `abuse.go`;
  per-peer/per-owner rate limiting still planned.)*
- **Authentication:** libp2p secure channels authenticate peers; root pointers are signed
  by the User's key. *(Planned — arrives with the network layer.)*
- **Acceptable use / abuse control:** enforced *locally per node*, since nodes are
  independent and untrusted — there is no global ban authority. A node combines per-owner
  storage quota + leases (§3.2, **[implemented]**) with the connection/flow defences above
  (rcmgr/connmgr/gater **[implemented]**; write-verb rate limiting **[planned]**).
  Ban-by-identity keys on the Ed25519 owner pubkey; to keep that ban meaningful, owner keys
  are **self-certifying** — minted via proof-of-work so a fresh identity costs
  seconds-to-minutes of CPU, not milliseconds. This is enforced end to end: the client mints
  under proof-of-work (`revika-ctl keygen -pow-difficulty`) and a node admits a
  PUT only from an owner meeting its own difficulty (`revika-node -pow-difficulty`,
  `Server.SetPoW`; `internal/cap/pow.go`, **[implemented]**). Repair and DELETE are exempt
  (repair regenerates already-admitted data and is mandatory; DELETE is owner-scoped). Since
  difficulty is per-node policy, a client storing across nodes must mint at the max
  difficulty among them (the puzzle is always Argon2id); the **policy advertisement**
  (`/revika/params`, `net.QueryParams`) lets a client learn each node's minimum difficulty up
  front — `revika-ctl connect` queries every bootstrap peer, takes the strictest, and mints a
  satisfying identity with no PoW flags, instead of hitting a late authorization error
  (**[implemented]**). A joining node
  reuses the same handshake (`net.FetchNodePolicy`, which superseded the PoW-only
  `FetchPoWPolicy`): with no `-bootstrap`-free seed flags it adopts and enforces its bootstrap
  peers' policy — the strictest PoW bar *and* the maintenance cadence (repair/rebalance, §3.4) —
  so only the seed node configures the cluster and both admission and maintenance propagate to
  every node that joins (**[implemented]**). Beyond admission, a node also defends its
  maintenance flows: `net.AbuseMonitor` locally blacklists a peer that rebalances off-schedule
  or lies about possession (§3.1/§3.4), its tuning a purely local knob never inherited from
  bootstrap. Hardened nodes may also run an **owner
  allowlist** (admission) instead of, or alongside, a blocklist.
- **Out of scope for the PoC (note as future work):** economic incentives/payments,
  Byzantine-fault-tolerant reputation, defenses against storage nodes that lie about
  possession beyond the probe mechanism, and **global** anti-Sybil measures (a cost to mint
  identities network-wide) — local per-node quota/rate-limits/blocklists above are *in*
  scope as planned work.

## 6. libp2p protocol surface

Versioned stream protocols (semantic-versioned IDs so upgrades are negotiable):

- `/revika/shard/1.2.0` — `PUT` / `GET` / `HAS` / `DELETE` a shard by ID. PUT carries the
  auth token, the stripe descriptor, the repair grant, and (since 1.2.0) a trailing
  `MoveReason` byte — `client` / `repair` / `rebalance` — so the receiver can distinguish a
  policed rebalance move from schedule-exempt repair regeneration (§3.1/§3.4). `1.1.0` (no
  reason byte, read as `repair`) is still served for back-compat; a client offers both IDs and
  libp2p's muxer picks the newest shared.
- `/revika/probe/1.0.0` — proof-of-possession challenge/response for the repair loop and the
  rebalancer's proof-gated release.
- `/revika/root/1.0.0` — optional direct fetch/publish of a User's signed root pointer
  (complements DHT publication).
- `/revika/params/1.0.0` — **[implemented]:** read-only node-policy advertisement. A node
  returns a `NodeParams` envelope (PoW admission + repair/rebalance maintenance cadence); a
  client (`connect`) or a joining node (`net.FetchNodePolicy`) reconciles it across bootstrap
  peers to inherit the cluster policy (§3.1/§5).
- `/revika/balance/1.0.0` — **[implemented]:** load report — a node answers a `QueryLoad`
  with its self-declared `LoadReport` (`used`/`capacity`/`shards`), letting a sampling peer
  compare normalized load `L = used/capacity` before deciding to shed to it (diffusion
  rebalancing, §3.4). Read-only and unauthenticated (a report reveals only aggregate counters,
  never shard content); the move itself rides the grant-authorized `PUT` on `/revika/shard`.

DHT usage:

- **Provider records — [implemented]:** `shardID → peers` (who holds a given shard),
  via `go-libp2p-kad-dht` on a private `/revika` protocol prefix (so revika runs its own
  Kademlia network — protocol `/revika/kad/1.0.0` — not a corner of the public IPFS DHT).
  Nodes also advertise themselves under the `revika/storage/1.0.0` rendezvous namespace so
  clients discover storage nodes with no central registry. See `internal/net/dht.go`
  (`Discovery`) and `placement.go` (`DHTStore`/`PlacementStore`).
- **Mutable records — [implemented]:** `user-pubkey → signed root pointer` (IPNS-like), a
  DHT value record validated by `rootValidator` (owner-binding + signature; highest `Seq`
  wins) with a complementary `/revika/root/1.0.0` node stream. See `internal/net/root.go`
  and `root_proto.go`; `provider.DHTRootStore`/`MultiRootStore` publish it behind the durable
  local `root.json`.

## 7. Repo layout (`✓` = implemented, rest planned)

```
cmd/
  revika-node/     ✓ headless Node server binary
  revika-ctl/      ✓ User client CLI (keygen/cp/ls/rm/share/node)
  revika-daemon/     # User background daemon (+ optional embedded node)  (planned)
internal/
  store/     ✓ content-addressed blob store (Mem + Disk); leases/quotas/GC TBD
  crypto/    ✓ AES-256-GCM AEAD; key derivation, signing TBD
  erasure/   ✓ Reed–Solomon encode/decode
  chunk/     ✓ fixed-size chunking (CDC planned)
  pipeline/  ✓ StoreFile/LoadFile + FileManifest (in-memory); StoreBlob/LoadBlob primitive
  repair/    ✓ availability probes + shard regeneration (local store)
  net/       ✓ libp2p host, protocol IDs, shard/probe handlers, NetStore client,
             Kademlia DHT (Discovery: bootstrap/provider records/node advertise),
             DHTStore + PlacementStore (discovery-backed store.Store's), signed
             root pointer publish/resolve (PutRoot/GetRoot + /revika/root stream)
  cap/       ✓ ML-KEM-768 capability wrapping (Wrap/Unwrap, FIPS 203) for sharing read-caps
  manifest/  ✓ ReadCap/VerifyCap/WriteCap cap chain, cap-addressed file/dir blobs
             (Merkle DAG), COW Graft, Rekey (revocation), signed RootPointer
             (persisted to root.json + published to the DHT)
  fsmeta/    ✓ capture/restore live-file attributes ⇄ pipeline.Metadata
             (POSIX split: Linux uid/gid/times/xattr, portable mode/mtime)
  provider/  ✓ framework-neutral OS-integration API (Provider iface) mapping
             File Provider / Cloud Filter / GVfs; Manifest impl over the DAG,
             stable ItemIDs + DAG-diff change enum, RootStore seam (§3.8)
  placement/   # richer node selection & redundancy policy (v1 round-robin
               # lives in internal/net for now); capacity-aware weights +
               # diffusion rebalancing (§3.4)                              (planned)
  ledger/      # per-user index/accounting, root-pointer management        (planned)
  sync/        # daemon folder-watch + reconcile (daemon only)            (planned)
  mount/       # OS filesystem integration: FUSE mountpoint (hanwen/go-fuse),
               # manifest-as-inode, LoadFile-on-open hydration, COW writes;
               # drives internal/provider; native bindings later          (planned)
```

## 8. Libraries

Currently in `go.mod`:

| Concern        | Library / package | Status |
|----------------|-------------------|--------|
| Erasure coding | `github.com/klauspost/reedsolomon` **v1.14.1** | in use |
| Symmetric AEAD | stdlib `crypto/aes` + `crypto/cipher` (AES-256-GCM) | in use |
| Hashing        | stdlib `crypto/sha256` (content addresses) | in use |
| P2P / transport / discovery | `github.com/libp2p/go-libp2p` (TCP+QUIC, Noise/TLS, Kademlia DHT) | in use |
| DHT discovery / provider records | `github.com/libp2p/go-libp2p-kad-dht` (`/revika` prefix) | in use |
| Cap wrapping   | stdlib `crypto/mlkem` (ML-KEM-768, FIPS 203) + AES-256-GCM DEM | in use |

Planned as later layers land:

| Concern            | Library |
|--------------------|---------|
| Signing / KDF | `crypto/ed25519` (root pointers), `golang.org/x/crypto/hkdf` |
| Local metadata DB  | `go.etcd.io/bbolt` (or SQLite) |
| Filesystem watching (daemon) | `github.com/fsnotify/fsnotify` |
| Content-defined chunking | a FastCDC implementation |
| OS filesystem mount (FUSE) | `github.com/hanwen/go-fuse` (Linux/macFUSE/WinFsp); native `FileProvider` (macOS) / Cloud Filter (Windows) per-OS, later |

> **Toolchain:** `go.mod` declares `go 1.26`; the environment's base `go` may be older, so
> `GOTOOLCHAIN=auto` (the default) fetches 1.26 on first build. Module path is `revika`.

## 9. Build order (walk before you run)

Prove the core loop before adding breadth. Each phase is independently testable.

1. ✅ **Core encoding, against the mock store.** chunk → encrypt → erasure-code →
   `Put`/`Get` against an in-memory/on-disk store → decode → decrypt → reassemble.
   Round-trips and any-`k`-of-`n` reconstruction verified on both stores.
2. ✅ **Repair loop, still on the mock store.** Delete shards, confirm `Check` detects the
   deficit and `Repair` restores redundancy (with address-stable regeneration).
3. ✅ **Real network.** `internal/net` puts the shard store on libp2p: a `Server`
   serving the `/revika/shard` + `/revika/probe` stream protocols, and a `NetStore`
   client that *is* a `store.Store` — so §3.2's seam holds and the encode and repair
   stacks run unchanged over the wire (proven by `TestPipelineOverNetwork`). The
   `revika-node` daemon is runnable. The **Kademlia DHT** (`Discovery`) adds serverless
   WAN discovery: nodes announce provider records for the shards they hold and advertise
   themselves as storage nodes; a client places a file's shards across several
   DHT-discovered nodes (`PlacementStore`) and retrieves them by provider discovery
   (`DHTStore`) with no explicit `-node` — verified end-to-end across a 3-node DHT and by
   `TestPlacementEndToEnd`. **Still open:** richer placement policy and repairing onto
   *fresh* nodes.
4. 🟡 **Metadata + mutable root** (in progress). The file manifest now serializes to JSON
   (manifest v4) carrying a full `Metadata` record — mode, owner, the four timestamps,
   attribute flags, content type, symlink target, xattrs, and content/metadata version
   tokens — so a manifest is mount-ready for the native cloud-provider frameworks (§3.6, §3.8);
   `revika-ctl` captures it on `cp` (store) and restores it on `cp` (retrieve).
   **Still open:** encrypting the manifest blob, encrypted directories, and signed root pointers.
5. 🟡 **Sharing** (in progress). Cap *delivery* is implemented (`internal/cap`:
   `Wrap`/`Unwrap` to a recipient's ML-KEM-768 key) and driven by `revika-ctl share rvk:<path>`.
   `share` resolves a path in the owner's namespace and seals a **shared root** — a
   `RootPointer` anchored at that file or subtree, signed by the sharer and wrapped to the
   recipient's key (§3.5) — so a tree owner can share one file or subtree without re-uploading
   it and without exposing anything outside the shared path. The recipient opens it with
   `-root <sealed> -key <priv>` and browses/reconstructs with `ls`/`cp`, which auto-detect
   file vs. subtree from the cap's `Kind` (in-process `TestNamespaceE2E`). **Still open:** the
   write-cap → read-cap → verify-cap derivation chain and signing keys for mutable objects.
6. ⬜ **Sync daemon.** Folder watching, reconcile, conflict handling; optional embedded
   node.
7. ⬜ **OS filesystem mount.** Expose the metadata tree from step 4 as a mounted filesystem
   via FUSE (`internal/mount`, `hanwen/go-fuse`): manifest-as-inode for `stat`/`readdir`,
   `LoadFile`-on-`open` hydration, and COW writes that advance the signed root pointer. Native
   File Provider (macOS) / Cloud Filter (Windows) surfaces follow. Depends on step 4;
   complements the sync daemon (step 6) as a second user-facing surface (§3.8).

**Deliberately deferred:** payments/incentives, global consensus, Byzantine reputation,
anti-Sybil. Revisit once the core storage guarantees are solid.

### Testing conventions established in steps 1–6

- Store implementations share one conformance suite (`RunStoreTests`-style) run against
  both `MemStore` and `DiskStore`; higher layers table-test against both too.
- `erasure` asserts the any-`k`-of-`n` property over randomized (seeded) shard subsets.
- `crypto` has a `FuzzOpen` target; decryption/parse boundaries get fuzzed.
- Everything runs under `go test -race`; the repair package carries the capstone
  end-to-end test (multi-MB file → degrade → repair → byte-exact read-back).

## 10. Open questions

**Resolved during steps 1–6:** module path (`revika`), AEAD (AES-256-GCM), v1 chunking
(fixed-size, 4 MiB default), default erasure params (`k=4`, `m=2`), Go version (1.26).

Still open:

- If/when content-defined chunking replaces fixed-size, its parameters and target chunk
  size — and whether `k`/`m` should scale with file size / desired durability.
- Concrete on-disk/on-wire serialization for manifests and capabilities (and a compact
  string form for caps); where `FileManifest` finally lives.
- How User identity keys relate to libp2p peer identity keys.
- Placement policy details: diversity signals available in a libp2p network, reputation
  inputs, and repair thresholds/cadence.
- Rebalancing tuning and hardening (§3.4): default values for the load threshold `θ`, peer
  sample size, round period, and per-shard cooldown are shipped but unvalidated at scale;
  still open are persisting the cooldown across restarts (it is in-memory today), enforcing the
  failure-domain `Spread` invariant on a move, wiring the sensed capacity back into
  placement-time `WeightByFree`/`Spread`, and sourcing a *trustworthy* capacity figure given
  that a `LoadReport` is self-declared (ties into anti-Sybil and reputation, deferred).
- Lease durations and garbage-collection policy on nodes.
- How multi-device access for a single User shares the signing key (or delegates via
  additional caps).
- Mount-layer (§3.8) specifics: write semantics against immutable, content-addressed content
  (per-`close` COW vs. a write-back buffer that batches dirty chunks), local placeholder-cache
  and hydration/eviction policy, and how far the FUSE PoC goes before the native File Provider /
  Cloud Filter bindings are worth their per-OS cost.
- Fine-grained / revocable sharing beyond handing over a read-cap. **Proxy re-encryption
  (incl. IB-CPRE) is rejected for v1** (§3.5: breaks content-addressing/repair, needs a
  trusted PKG, and has no PQC-class standardized scheme); the near-term path is revocation
  via key rotation + the read-cap/verify-cap derivation chain. Revisit PRE only if a
  stdlib-grade lattice PRE without a trusted authority appears.
