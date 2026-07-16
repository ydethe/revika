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

This is the **Tahoe-LAFS** model, adapted to modern P2P plumbing (go-libp2p) and content
addressing (IPFS-style provider records).

## 3. Layered architecture

```
┌─────────────────────────────────────────────┐
│ Sync engine (daemon only)                     │  watch folder ⇄ network        [planned]
├─────────────────────────────────────────────┤
│ Filesystem / metadata layer                   │  dirs, manifests, mutable root [partial]
├─────────────────────────────────────────────┤
│ Capability & crypto layer                     │  per-object keys, caps         [partial]
├─────────────────────────────────────────────┤
│ Encoding pipeline                             │  chunk → encrypt → erasure  [implemented]
├─────────────────────────────────────────────┤
│ Placement / repair layer                      │  placement [planned] / repair [impl.]
├─────────────────────────────────────────────┤
│ Storage layer (Node)                          │  blob store by shardID      [implemented]
├─────────────────────────────────────────────┤
│ Network layer — go-libp2p                     │  identity, transport, DHT, NAT [planned]
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
- **Discovery** — Kademlia DHT (`go-libp2p-kad-dht`) for the WAN, mDNS for LAN.
- **NAT traversal** — AutoNAT, hole-punching (DCUtR), and relay for peers behind NAT.

Do not roll a bespoke wire protocol. All revika interactions are **libp2p stream
protocols** with versioned protocol IDs (see §6).

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
abandoned shards are GC'd), **quotas** (per-node capacity, per-user accounting), and the
**proof-of-possession** probe endpoint (§3.4) — these arrive with the network layer,
since only a networked node needs them. `.revika/shards/` is the intended on-disk root.

### 3.3 Encoding pipeline (User) — **[implemented]** (`internal/pipeline`, `chunk`, `crypto`, `erasure`)

`StoreFile(ctx, store, cfg, reader) → FileManifest` runs the store path chunk by chunk;
`LoadFile(ctx, store, manifest, writer)` runs it in reverse. `Config` is
`{ChunkSize int; Params erasure.Params}` (default 4 MiB chunks, `k=4`, `m=2`).

1. **Chunk** (`internal/chunk`) — **fixed-size** for now, exposed as a Go
   `iter.Seq2[[]byte, error]`. Content-defined chunking (FastCDC-style rolling hash, so
   an edit only rewrites the affected chunk) is a **[planned]** upgrade behind the same
   iterator contract.
2. **Encrypt** (`internal/crypto`) — each chunk gets a fresh random key and is sealed
   with **AES-256-GCM** (stdlib `crypto/aes`+`crypto/cipher`; 12-byte random nonce
   prepended). AES-GCM was chosen over XChaCha20-Poly1305 to avoid an external
   dependency; it is isolated behind `Seal`/`Open` and swappable. Per-object random keys
   avoid the equality-leak of convergent encryption.
3. **Erasure-code** (`internal/erasure`) — Reed–Solomon (`klauspost/reedsolomon`) splits
   the *encrypted* chunk into `k` data + `m` parity shards; any `k` of the `k+m`
   reconstruct it. An 8-byte length header is prepended so `Decode` recovers the exact
   original length despite RS zero-padding. **`Encode` is deterministic** — the same
   input always yields byte-identical shards (this is what makes repair address-stable,
   §3.4).
4. **Address & store** — each shard is `Put` into the `Store`; its `shardID = hash(shard)`
   is recorded in the chunk's `ChunkRef`.

Retrieval fetches whatever shards are available (missing/corrupt ones are tolerated up
to the erasure margin) → erasure-decode → decrypt → reassemble.

### 3.4 Placement / repair layer

**Placement — [planned].** Choose `n = k + m` distinct nodes per encoded chunk,
optimizing for *diversity* (spread across independent nodes / network / operator domains
so correlated failures don't drop below `k`), *reliability* (uptime/reputation), and
*proximity/cost* (secondary). After placement, announce **provider records** to the DHT:
`shardID → {peers holding it}`. None of this exists yet — the current pipeline stores
every shard into one local `Store`.

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

Still **[planned]**: the network-side **proof-of-possession** probe (so a remote node
proves possession without shipping the shard), placing regenerated shards on *fresh*
nodes rather than back into the same store, and the repair *cadence*/threshold policy
(who runs it, how often, what margin triggers it).

### 3.5 Capability & crypto layer — **[partial]** (`internal/crypto`)

**Implemented:** symmetric authenticated encryption only — `NewKey`, `Seal`, `Open`
(AES-256-GCM), which is what the pipeline uses for per-chunk encryption. **Planned:**
the capability model and all asymmetric key material below.

The **capability** ("cap") is how access is named and delegated, following Tahoe-LAFS:

- A **read-capability** = *manifest location* + *decryption key(s)*. Whoever holds it can
  read the object. Nothing else is needed, and nodes never see it.
- A **write-capability** for mutable objects = a signing private key; possession lets you
  publish new versions.
- Derivation chain: **write-cap → read-cap → verify-cap**. Each level can be derived from
  the one above but not below, so you can hand out exactly the privilege you intend:
  - write-cap: full read/write,
  - read-cap: read only,
  - verify-cap: check integrity/repair without reading plaintext (lets a repairer or node
    validate shards without decryption rights).

**Key material:**

- per-chunk/per-object symmetric keys (random),
- per-User asymmetric identity keys (X25519 for cap delivery, Ed25519 for signing root
  pointers) — kept in `.revika/keys/`,
- libp2p peer keys for network identity.

For the planned pieces, use `crypto/ecdh` (X25519) or `golang.org/x/crypto/nacl/box` for
wrapping caps to recipients, `hkdf` for key derivation, and stdlib `crypto/ed25519` for
signatures. (Chunk encryption already uses stdlib AES-256-GCM, so no `x/crypto`
dependency exists yet.)

### 3.6 Filesystem / metadata layer — **[partial]**

- **File manifest** — **[partial]**. `pipeline.FileManifest` exists today as an in-memory
  value: ordered `ChunkRef`s (per-chunk key + ordered shard IDs), the `Config`, and total
  size. Still **[planned]**: serializing it, encrypting it, storing it as an immutable
  blob whose read-cap is the file's read-cap, provider hints, and moving the type into
  `internal/manifest`.
- **Directory** — **[planned]**. An encrypted map of names → child caps (files or
  subdirectories), itself an immutable blob. A directory tree is thus a Merkle-ish DAG of
  encrypted blobs.
- **Root pointer** — **[planned]**. The one mutable anchor per User (see §4).

### 3.7 Sync engine (daemon only) — **[planned]**

OneDrive-style: watch a local folder (`fsnotify`), diff against the last-known state,
and reconcile:

- local change → run the store pipeline, update manifests/directory, publish new root;
- remote change (newer root observed) → fetch and materialize into the local folder;
- conflicts → resolved by sequence number + a conflict-copy fallback (never silently lose
  data).

## 4. Mutable state without global consensus — **[planned]**

Distributed *mutable* state is the hardest part. **Do not use a blockchain** — it is
overkill for this workload and for a PoC. (None of this is built yet; the current
pipeline returns an in-memory manifest with no persisted root.)

Design:

- Everything content-addressed (chunks, manifests, directories) is **immutable** and
  freely cacheable/dedup-able.
- The only mutable thing is a small, per-User **root pointer**: a signed record mapping
  `user-signing-pubkey → latest-root-directory-hash`, carrying a **monotonic sequence
  number** and timestamp.
- Publish it IPNS-style: store on the DHT keyed by the pubkey, and/or on a set of the
  user's chosen nodes. Readers verify the signature and take the highest sequence number.
- Conflict resolution is single-writer-per-key by construction (only the holder of the
  signing key can advance the sequence); multi-device writes for the same user reconcile
  via sequence + conflict copies in the sync layer.

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
  are chosen for target durability.
- **Authentication:** libp2p secure channels authenticate peers; root pointers are signed
  by the User's key. *(Planned — arrives with the network layer.)*
- **Out of scope for the PoC (note as future work):** economic incentives/payments,
  Byzantine-fault-tolerant reputation, defenses against storage nodes that lie about
  possession beyond the probe mechanism, and anti-Sybil measures.

## 6. libp2p protocol surface

Versioned stream protocols (semantic-versioned IDs so upgrades are negotiable):

- `/revika/shard/1.0.0` — `PUT` / `GET` / `HAS` / `DELETE` a shard by ID (with lease
  parameters on PUT).
- `/revika/probe/1.0.0` — proof-of-possession challenge/response for the repair loop.
- `/revika/root/1.0.0` — optional direct fetch/publish of a User's signed root pointer
  (complements DHT publication).

DHT usage:

- **Provider records:** `shardID → peers` (who holds a given shard).
- **Mutable records:** `user-pubkey → signed root pointer` (IPNS-like).

## 7. Repo layout (`✓` = implemented, rest planned)

```
cmd/
  revika-node/       # headless Node server binary                        (planned)
  revika-daemon/     # User background daemon (+ optional embedded node)  (planned)
internal/
  store/     ✓ content-addressed blob store (Mem + Disk); leases/quotas/GC TBD
  crypto/    ✓ AES-256-GCM AEAD; key derivation, capabilities, signing TBD
  erasure/   ✓ Reed–Solomon encode/decode
  chunk/     ✓ fixed-size chunking (CDC planned)
  pipeline/  ✓ StoreFile/LoadFile + FileManifest (in-memory)
  repair/    ✓ availability probes + shard regeneration (local store)
  net/         # libp2p host setup, protocol IDs, stream handlers         (planned)
  manifest/    # file/dir manifest & capability types + serialization     (planned)
  placement/   # node selection & redundancy policy                       (planned)
  ledger/      # per-user index/accounting, root-pointer management        (planned)
  sync/        # daemon folder-watch + reconcile (daemon only)            (planned)
```

## 8. Libraries

Currently in `go.mod`:

| Concern        | Library / package | Status |
|----------------|-------------------|--------|
| Erasure coding | `github.com/klauspost/reedsolomon` **v1.14.1** | in use |
| Symmetric AEAD | stdlib `crypto/aes` + `crypto/cipher` (AES-256-GCM) | in use |
| Hashing        | stdlib `crypto/sha256` (content addresses) | in use |

Planned as later layers land:

| Concern            | Library |
|--------------------|---------|
| P2P / discovery / NAT | `github.com/libp2p/go-libp2p`, `go-libp2p-kad-dht` |
| Cap wrapping / signing / KDF | `crypto/ecdh` (X25519), `crypto/ed25519`, `golang.org/x/crypto` (nacl/box, hkdf) |
| Local metadata DB  | `go.etcd.io/bbolt` (or SQLite) |
| Filesystem watching (daemon) | `github.com/fsnotify/fsnotify` |
| Content-defined chunking | a FastCDC implementation |

> **Toolchain:** `go.mod` declares `go 1.26`; the environment's base `go` may be older, so
> `GOTOOLCHAIN=auto` (the default) fetches 1.26 on first build. Module path is `revika`.

## 9. Build order (walk before you run)

Prove the core loop before adding breadth. Each phase is independently testable.

1. ✅ **Core encoding, against the mock store.** chunk → encrypt → erasure-code →
   `Put`/`Get` against an in-memory/on-disk store → decode → decrypt → reassemble.
   Round-trips and any-`k`-of-`n` reconstruction verified on both stores.
2. ✅ **Repair loop, still on the mock store.** Delete shards, confirm `Check` detects the
   deficit and `Repair` restores redundancy (with address-stable regeneration).
3. ⬜ **Real network** ← *next*. Swap the mock store for a libp2p-backed `Store`:
   `revika-node` serving the shard/probe protocols, DHT provider records, multi-node
   placement. Because §3.2's `Store` is the seam, steps 1–2 should run unchanged on top.
4. ⬜ **Metadata + mutable root.** Serialize/encrypt manifests, encrypted directories,
   signed root pointers.
5. ⬜ **Sharing.** Read/write/verify capabilities and cap delivery wrapped to recipient
   keys.
6. ⬜ **Sync daemon.** Folder watching, reconcile, conflict handling; optional embedded
   node.

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
  string form for caps, à la Tahoe URIs); where `FileManifest` finally lives.
- How User identity keys relate to libp2p peer identity keys.
- Placement policy details: diversity signals available in a libp2p network, reputation
  inputs, and repair thresholds/cadence.
- Lease durations and garbage-collection policy on nodes.
- How multi-device access for a single User shares the signing key (or delegates via
  additional caps).
