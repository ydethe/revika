# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**The offline core loop, the networked Node role, a User-side client CLI
(store/retrieve/share), and the Kademlia DHT (WAN discovery + provider records +
multi-node placement + autonomous node-side repair) are implemented; the
background User daemon and manifests-as-network-blobs are not.** Build-order steps 1–3 pass `go test -race`
(offline pipeline: chunk → encrypt → erasure-code → store → retrieve → **repair**;
plus the libp2p network layer with a runnable `revika-node` daemon), the DHT layer
lets a client place a file's shards across several discovered nodes and retrieve
them by provider discovery **with no explicit node and no central server**, and a
first cut of step 5 (**sharing** via capability wrapping) ships in `revika-ctl`.
The Node also has a first cut of **authorization, leases/quotas, and garbage
collection**: a per-node SQLite **ledger** (`internal/ledger`) tracks who owns
each shard, PUT/DELETE carry a signed **auth token** (User Ed25519 key), DELETE
only drops the caller's own claim (a blob is freed once its last owner leaves),
per-owner **quotas** are enforced, and a GC loop reclaims unowned shards.
**Autonomous node-side repair** is now implemented: at store time each shard
carries a non-confidential **stripe descriptor** (K/M + sibling shard IDs, no key)
and a User-signed **repair grant**, both recorded in the node ledger; a background
repair loop on each node probes the stripes it holds over the DHT and, when a
stripe has lost shards but still has ≥K, regenerates the missing shards onto fresh
nodes with no User online — authorized by the grant, operating purely on
ciphertext. There is as yet **no background User daemon (`revika-daemon`), no sync
engine, no IPNS-like mutable root pointer, and no directories**. Node-selection policy is a
first cut (round-robin placement); reputation/diversity domains are future work.
Manifests are persisted by the client as local JSON files (the interim read-cap),
not yet as encrypted network blobs. Lease expiry is advisory (own-until-delete);
expiry-driven GC is off by default until a daemon can renew. Verify against the
actual tree before relying on any path or type not listed as implemented, and
update this file as more lands.

Implemented packages (see [Architecture.md](Architecture.md) for detail):

| Package | Role |
|---------|------|
| `internal/store`   | content-addressed blob store: `Store` iface + `MemStore` + `DiskStore` |
| `internal/crypto`  | AES-256-GCM AEAD (stdlib): `NewKey`/`Seal`/`Open` |
| `internal/erasure` | Reed–Solomon `Encode`/`Decode` (`klauspost/reedsolomon`) |
| `internal/chunk`   | fixed-size chunker (`iter.Seq2`); CDC is a planned upgrade |
| `internal/pipeline`| `StoreFile`/`LoadFile` + `FileManifest`; wires the four above |
| `internal/repair`  | `Check` (probe) + `Repair` (regenerate missing shards) |
| `internal/net`     | libp2p host + `/revika/shard` & `/revika/probe` protocols; `Server` (Node, ledger-gated PUT/DELETE) + `NetStore`/`NewNetStoreSigned` (a `store.Store` over the wire, optionally signing writes); signed **auth tokens** (`auth.go`); **`Discovery`** (Kademlia DHT: bootstrap, provider records, node-service advertise/find) + **`DHTStore`**/**`PlacementStore`** (`store.Store`s that discover providers and spread shards across nodes) + **`RepairStore`** (a per-stripe store that reads via the DHT and places regenerated shards on fresh nodes, authorized by a repair grant) |
| `internal/cap`     | User identity: ML-KEM-768 `Wrap`/`Unwrap` (FIPS 203 KEM + AES-256-GCM DEM) for sharing a read-cap, **plus Ed25519 `SignKey`/`SignPubKey`** (`signing.go`) — the signing identity that authorizes storing/deleting shards |
| `internal/stripe`  | non-confidential erasure metadata for repair: `Descriptor` (K/M + ordered sibling shard IDs, **no key**) with `MarshalBinary`/`UnmarshalDescriptor`/`Contains`; signed **repair grant** `BuildGrant`/`VerifyGrant`; `Putter` optional store interface |
| `internal/ledger`  | per-node SQLite index (`modernc.org/sqlite`): shard ownership (refcount by owner), leases, per-owner quotas, **stripe descriptors + repair grants** (FK-cascaded to the shard); `AddOwner`/`RemoveOwner`/`CollectRecord`/`Collectible`/`Reconcile`/`PutStripe`/`Stripes` |
| `cmd/revika-node`  | headless Node daemon: serves shards from a `DiskStore` gated by the ledger, persistent libp2p identity, mDNS, DHT server (announces held shards, advertises as a storage node, periodic reprovide), quota/lease flags + GC loop + **repair loop** (probes held stripes, regenerates missing shards onto fresh nodes) |
| `cmd/revika-ctl`   | User client CLI: `keygen`/`put`/`get`/`delete`/`share` — drives the pipeline over a single node (`-node`) or DHT-discovered nodes (`-bootstrap`/`-mdns`), signs writes with the User signing key (`-signkey`), manifests as local JSON |

### Toolchain & key decisions made during implementation

- **`go.mod` module path is `revika`** (bare). Rename via `go mod edit -module <path>`
  plus an import rewrite if a `github.com/...` path is wanted.
- **Go 1.26** (`go 1.26` in `go.mod`). The system `go` is older, so `GOTOOLCHAIN=auto`
  auto-downloads 1.26 on first build — leave `GOTOOLCHAIN` at its default.
- **AEAD = AES-256-GCM from the standard library**, not XChaCha20, to avoid an external
  crypto dependency. Isolated behind `crypto.Seal`/`Open`, so it is swappable. AES-256
  is itself post-quantum-safe (Grover only halves the key strength → 128-bit), so it is
  kept for shard encryption and reused as the DEM under ML-KEM (below).
- **Cap sharing = ML-KEM-768 (NIST FIPS 203), PQC.** The read-cap wrapping in
  `internal/cap` uses the `crypto/mlkem` standard library (no external dependency) as a
  KEM-DEM: `Wrap` encapsulates against the recipient's public key for a fresh shared
  secret and prepends the KEM ciphertext to an AES-256-GCM seal of the payload; `Unwrap`
  decapsulates with the private key. This replaced the previous X25519/NaCl-box anonymous
  seal to satisfy the PQC requirement (Specifications.md PK004). Keys are now larger
  (public 1184 B, private = 64 B seed, KEM ciphertext 1088 B), still base64 text on disk.
  **Signatures stay classical Ed25519** — FIPS 203 is a KEM only; PQC signatures (FIPS 204
  ML-DSA) are not yet in the Go stdlib and remain future work.
- **Reed–Solomon = `klauspost/reedsolomon` v1.14.1.**
- **Chunking is fixed-size** for now (`chunk.DefaultSize` = 4 MiB); content-defined
  chunking can replace it behind the same iterator contract.
- **Default erasure = `k=4`, `m=2`** (`pipeline.DefaultConfig`); not yet tuned.
- **Repair needs no decryption key** — it operates on ciphertext shards and relies on
  `erasure.Encode` being deterministic, so regenerated shards reproduce their original
  content addresses and the manifest never changes.
- **DHT = `go-libp2p-kad-dht` with a `/revika` protocol prefix**, so revika runs its
  *own* private Kademlia network (protocol `/revika/kad/1.0.0`), isolated from the
  public IPFS DHT. Provider records key `shardID → holders` via a CIDv1 (raw codec)
  wrapping the shard's SHA-256; nodes advertise themselves under the `revika/storage`
  rendezvous namespace so clients can discover storage nodes with no registry.
- **Placement = round-robin across discovered nodes** (`net.PlacementStore`), so a
  chunk's `k+m` shards land on distinct nodes when enough are available. This is the
  first cut of the planned placement layer; it currently lives in `internal/net`.
- **Authorization = signed User-key tokens, verified at the Server; the Store stays
  identity-free.** A User has an Ed25519 signing key (separate from the ML-KEM cap
  key and from the libp2p peer identity). Each PUT/DELETE carries a token
  `ownerPubKey ‖ timestamp ‖ sig`, signed over `op ‖ shardID ‖ nodePeerID ‖ ts`
  (see `internal/net/auth.go`). Binding the node scopes a token to one Node and the
  timestamp bounds replay (±5 min); replay is harmless because writes are
  owner-scoped and idempotent. The wire always carries the token blob (empty when
  the client has no signer), so a nil-ledger `Server` stays backward-compatible.
- **Ownership = refcount by owner.** Content addressing dedups identical bytes, so a
  shard has a *set* of owner keys; DELETE drops only the caller's claim and the blob
  is physically removed only when the last owner leaves. Quotas charge each owner the
  full shard size on their first claim (predictable; a re-PUT is a free renewal).
- **Ledger = SQLite via `modernc.org/sqlite`** (pure Go, cgo-free — matches the
  cgo-free stance). Blobs on disk are the source of truth for *bytes*; the ledger is
  the source of truth for *ownership*. `Reconcile` on startup retains orphan blobs
  (no data loss on upgrade) and drops records whose blob is gone.
- **GC ordering** favours self-heal: a grace window (collectible two cycles running)
  plus an atomic `CollectRecord` that drops a record only if still unowned, so a
  racing re-PUT (which re-creates the content-addressed blob) is never clobbered.
- **DHT queries must wait for routing-table readiness** (`Discovery.WaitReady`)
  before the first lookup — the table fills asynchronously after bootstrap, so
  querying immediately races an empty table and finds nothing.
- **Repair is node-side, enabled by a non-confidential stripe descriptor +
  repair grant distributed at store time.** A dumb node can't repair what it can't
  reason about, so each shard is stored with its `stripe.Descriptor` (K/M + the
  ordered sibling shard IDs — deliberately *not* the encryption key, so it leaks no
  plaintext) and a User-signed `stripe` **repair grant**. The grant authorizes
  storing *any shard whose content address is in this stripe*, attributed to the
  granting User; content addressing bounds it to exactly the stripe's bytes, so it
  can't be used to store arbitrary data. Both are recorded in the node ledger
  (FK-cascaded to the shard) and replayed when a regenerated shard is placed on a
  fresh node — so repair works **with no User online** and no User key on the node.
  Regeneration reuses `internal/repair` unchanged (it operates on ciphertext and
  never touches `ChunkRef.Key`; `erasure.Encode` is deterministic so regenerated
  shards reproduce their content addresses).
- **A repairing node reads survival from its own store first, then the DHT**
  (`net.RepairStore` wraps `DHTStore` with the node's local `blobs`). The DHT's
  `FindProviders` deliberately excludes the querying host, so a node cannot discover
  its *own* shards over the DHT; a repairer that only asked the DHT would count
  every shard it holds locally as missing and wrongly declare an
  otherwise-recoverable stripe unrecoverable (present < K) — so no repair would ever
  fire on the very nodes best placed to run it. `RepairStore.Has`/`Get` consult the
  local store first to close that blind spot; `Put` still places regenerated shards
  on *remote* fresh nodes and now tries every fresh candidate (skipping stale
  adverts for peers that have gone away) rather than a single round-robin pick.
- **No repair coordinator election (v1).** Every holder of a degraded stripe may
  regenerate; a small per-stripe jitter plus the fact that `repair.Repair`
  re-fetches survivors first (and stores nothing when a sibling has reappeared)
  makes duplicate work rare and always harmless — content-addressed `Put` and
  per-owner `AddOwner` are idempotent. Min-position election is a planned
  optimization.
- **Grant tradeoff (v1):** a repair grant is a *standing* owner-write capability
  for its stripe (a malicious holder could re-PUT the stripe's own bytes, e.g.
  resurrect a deleted shard, re-charging the owner — bounded to those exact bytes).
  A reserved `expiry` field ships now (`-grant-ttl`, default 0 = never); full
  revocation is a follow-up.
- **Shard protocol bumped to `/revika/shard/1.1.0`.** The PUT frame gained two
  trailing length-prefixed blobs after the auth token — the stripe descriptor and
  repair grant (empty when unused) — so the framing stays uniform. Cross-version
  peers fail cleanly at multistream negotiation rather than deadlocking.

## What revika is

A decentralized, distributed, end-to-end encrypted storage system — think a
self-hosted Dropbox/Drive that runs over a peer-to-peer network instead of a central
server. Files are split, encrypted, and spread across many independent nodes so that
no single node holds a whole file and the system tolerates node loss.

### Roles

- **User** — wants to store, retrieve, and share their data. Holds the encryption
  keys. Interacts with the network through the User daemon.
- **Node** — a server that stores *shards* of data on behalf of one or more users.
- A single machine can act as both (a User who also contributes storage as a Node).

### Release artifacts (two binaries)

- **Node server** — headless binary for server-only participation (Node role).
- **User daemon** — a background service (macOS/Windows, OneDrive-style) that syncs a
  local folder to the network, handles retrieval, and *optionally* also runs the Node
  service in-process.

## Core design decisions

These are settled; treat them as constraints unless the maintainer changes them.

- **Sudo commands** : if you need a sudo command, ask me to run. I will run it in a separate terminal and provide the output.
- **Redundancy = erasure coding**, not plain replication. Files are split into `k`
  data shards + `m` parity shards; any `k` of the `k+m` shards reconstruct the file
  ("RAID-5/6 over the internet"). Prefer a mature Go Reed–Solomon library
  (e.g. `klauspost/reedsolomon`) over hand-rolling.
- **Networking = go-libp2p** (`github.com/libp2p/go-libp2p`). Use it for:
  - peer discovery — Kademlia DHT for the WAN, mDNS for LAN;
  - NAT traversal / hole-punching;
  - authenticated, encrypted, multiplexed transport.
  Do not roll a bespoke wire protocol; build revika's protocols as libp2p stream
  protocols with versioned protocol IDs.
- **Everything is encrypted.** Data is encrypted client-side (User) before shards ever
  leave the machine; nodes store ciphertext shards and cannot read content.
- **Sharing** works through a system of User encryption keys — granting access means
  sharing/wrapping keys, not copying plaintext.

### Concepts to keep straight

The `.gitignore` reserves `.revika/` for persisted runtime state: **node shares,
ledger, keys, and a mock store**. Expected meanings:

- **shard/share** — an erasure-coded, encrypted piece of a file stored on a Node.
- **ledger** — *implemented as* the node-side SQLite ownership/lease/quota index
  (`internal/ledger`, at `.revika/ledger/ledger.db`); *not* a global blockchain. A
  separate per-user index / root pointer is still planned.
- **keys** — User encryption keys (ML-KEM-768, FIPS 203), the User signing key (Ed25519, the
  storage owner identity), and node identity keys (libp2p peer identity).
- **mock store** — an in-development storage backend standing in for real distributed
  storage, so components can be built/tested before the network layer is complete.

## Architecture (condensed)

Full detail lives in [Architecture.md](Architecture.md). The essentials:

**Guiding principle — nodes are dumb, untrusted blob stores.** They only ever see
encrypted, erasure-coded shards addressed by content hash. All intelligence (chunking,
encryption, keys, sharing) lives on the User side, so a node is trusted for
*availability* but never *confidentiality*. This is the Tahoe-LAFS model.

**Layers (bottom → top):** go-libp2p network → Node disk blob store → placement/repair
→ encoding pipeline (chunk → encrypt → erasure-code) → capability & crypto → filesystem/
metadata → sync engine (daemon only).

**Three flows:**
- *Store* — chunk (content-defined) → per-chunk random key + AEAD encrypt → Reed–Solomon
  `k`+`m` shards → `shardID = hash(shard)` → PUT to `n` diverse nodes + announce to DHT →
  update encrypted manifest & signed root pointer.
- *Retrieve* — resolve root → decrypt manifest → DHT-lookup providers → fetch any `k` of
  `n` shards → erasure-decode → decrypt → reassemble.
- *Share* — a **read-capability** = manifest location + decryption key; wrap it with the
  recipient's public key. No shards copied; nodes learn nothing. Cap derivation chain:
  write-cap → read-cap → verify-cap.

**Two hard parts, designed deliberately:**
1. **Mutable state without global consensus** — each User's filesystem is authoritative
   locally, backed to the network as immutable encrypted blobs plus one mutable, signed
   **root pointer** (`pubkey → latest-root-hash`, IPNS-style, monotonic sequence). No
   blockchain.
2. **Repair is mandatory** — erasure coding without repair only delays data loss. A
   maintenance loop probes shard availability (proof-of-possession) and regenerates
   missing shards when redundancy drops below threshold.

**Key libraries:** `go-libp2p` (+ `go-libp2p-kad-dht`), `klauspost/reedsolomon`,
stdlib `crypto/mlkem` (ML-KEM-768, FIPS 203) + `crypto/aes`, `golang.org/x/crypto`
(hkdf), `bbolt`/SQLite, `fsnotify`.

**libp2p protocols:** `/revika/shard/1.0.0` (PUT/GET/HAS/DELETE), `/revika/probe/1.0.0`
(proof-of-possession), DHT provider records for shard location, IPNS-like signed records
for root pointers.

**Build order (PoC — walk before run):** prove the core loop first — chunk → encrypt →
erasure-code → distribute → retrieve → **repair** — against the mock store, then swap the
mock for real libp2p nodes. Sharing and the sync daemon come after. Defer payment/
incentive layers, global consensus, and Byzantine reputation.

## Commands

Standard Go toolchain (the `.claude` permissions are pre-approved for these):

```bash
go build ./...            # build everything
go test ./...             # run all tests
go test ./path/to/pkg     # test a single package
go test -run TestName ./path/to/pkg   # run a single test
go vet ./...              # static checks
go run ./cmd/revika-node  # Node daemon (flags: -data, -listen, -mdns, -dht, -bootstrap, -advertise,
                          #   -quota, -lease-ttl, -gc-interval, -gc-expired-leases,
                          #   -repair, -repair-interval, -v)
go run ./cmd/revika-ctl   # User client: keygen | put | get | delete | share (see -h)
```

`keygen` now writes two keypairs: `<prefix>.key/.pub` (ML-KEM-768, for receiving shares)
and `<prefix>.sign.key/.sign.pub` (Ed25519, the storage owner identity). `put`/`delete`
sign with `-signkey` (default `.revika/keys/user.sign.key`); only the signing-key holder
can `delete` what they stored.

Multi-node DHT run (no central server; the client never names a node):

```bash
go run ./cmd/revika-node -listen /ip4/127.0.0.1/tcp/4001            # seed; note its /p2p/ multiaddr => $A
go run ./cmd/revika-node -listen /ip4/127.0.0.1/tcp/4002 -bootstrap $A
go run ./cmd/revika-node -listen /ip4/127.0.0.1/tcp/4003 -bootstrap $A
go run ./cmd/revika-ctl put -bootstrap $A -manifest f.json file.bin  # shards spread across discovered nodes
go run ./cmd/revika-ctl get -bootstrap $A -manifest f.json -o out.bin # providers found via the DHT
```

Runtime state is written under `.revika/` and is git-ignored. Compiled binaries
(`/revika`, `/revika-node`, `/revika-daemon`) are also git-ignored — adjust these
names in `.gitignore` if the final binary names differ.

### Repo layout (`✓` = implemented, rest planned)

```
cmd/revika-node/   ✓ headless Node daemon           cmd/revika-daemon/  (planned)
cmd/revika-ctl/    ✓ User client CLI (keygen/put/get/delete/share)
internal/
  store/     ✓ content-addressed blob store (Mem + Disk)
  crypto/    ✓ AES-256-GCM AEAD; key derivation TBD
  erasure/   ✓ Reed–Solomon encode/decode
  chunk/     ✓ fixed-size chunking (CDC planned)
  stripe/    ✓ non-confidential erasure metadata (Descriptor) + signed repair grant
  pipeline/  ✓ StoreFile/LoadFile + FileManifest (in-memory manifest for now)
  repair/    ✓ availability probes + shard regeneration
  net/       ✓ libp2p host, protocol IDs, shard/probe handlers, NetStore client
             (signed writes + auth tokens + stripe/grant PUT), ledger-gated Server,
             Kademlia DHT (Discovery), DHTStore + PlacementStore + RepairStore
  cap/       ✓ ML-KEM-768 cap wrapping (Wrap/Unwrap, FIPS 203) + Ed25519 signing identity
  ledger/    ✓ per-node SQLite ownership/lease/quota + stripe index (node-side)
  manifest/    on-disk/on-wire manifest + capabilities      (planned)
  placement/   node selection & redundancy policy — first cut (round-robin) lives
               in internal/net for now; a richer policy (reputation, diversity
               domains) is still planned here
  sync/        daemon folder-watch + reconcile (daemon only) (planned)
```

Note: the per-user index / root pointer originally sketched for `internal/ledger`
is still planned; the `internal/ledger` that exists today is the *node-side*
ownership/quota ledger.

Note: `FileManifest`/`ChunkRef` currently live in `internal/pipeline` as in-memory
values; `cmd/revika-ctl` serializes them to local JSON (the interim read-cap, hex keys
+ shard IDs). When network serialization lands they are expected to move to
`internal/manifest`. `internal/cap` already provides the recipient-key wrapping that
`share` uses to deliver a read-cap.

## Open questions (decide before/while implementing)

Resolved so far: module path (`revika`), AEAD (AES-256-GCM), chunking for v1 (fixed-size),
default erasure params (`k=4`, `m=2`), DHT = `go-libp2p-kad-dht` on a private `/revika`
prefix, provider-record key = CIDv1(raw, sha256(shard)), placement v1 = round-robin.
Also resolved: authorization = signed User-Ed25519-key tokens verified at the Server
(the User signing key is a *separate* identity from the libp2p peer key); node ledger =
SQLite (`modernc.org/sqlite`); ownership = refcount-by-owner; quotas enforced per-owner;
lease policy = own-until-delete (expiry advisory, expiry-GC off by default).
Still open:

- Content-defined chunking parameters, if/when CDC replaces fixed-size.
- Concrete cap/manifest serialization format (and where `FileManifest` finally lives).
- Whether `k`/`m` and shard sizing should vary by file size / durability target.
- Node selection policy beyond round-robin (diversity domains, reputation), where the
  placement code finally lives, and repair-diversity (spreading regenerated shards
  across failure domains). Repair onto fresh nodes is implemented; a repair
  *coordinator election* and threshold-driven scheduling (repair only near K, batched
  probes) are still open.
- Repair-grant hardening: revocation / rotation beyond the reserved `expiry`, so a
  compromised grant can't indefinitely resurrect deleted shards.
- Lease renewal once a User daemon exists (then expiry-driven GC can default on);
  GC grace-window tuning; provider-record reprovide cadence; proactive un-provide on GC.
- Token replay hardening beyond the ±5 min window (server-side nonce cache) if needed.
- Bootstrap-peer distribution (no hardcoded public list yet) and NAT/relay tuning.

See [Architecture.md](Architecture.md) for the reasoning behind each.
