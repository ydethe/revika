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
│ Sync engine (daemon only)                     │  watch folder ⇄ network        [planned]
├─────────────────────────────────────────────┤
│ Filesystem / metadata layer                   │  dirs, manifests, mutable root [partial]
├─────────────────────────────────────────────┤
│ Capability & crypto layer                     │  per-object keys, caps         [partial]
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
matter (the `revika-ctl put -bootstrap …` path). Each holding node announces a
**provider record** to the DHT (`shardID → {peers holding it}`) on receipt, keyed by a
CIDv1(raw codec) wrapping the shard's SHA-256; a client's `get` resolves those records to
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

Still **[planned]**: the network-side **proof-of-possession** probe (so a remote node
proves possession without shipping the shard), placing regenerated shards on *fresh*
nodes rather than back into the same store, and the repair *cadence*/threshold policy
(who runs it, how often, what margin triggers it).

### 3.5 Capability & crypto layer — **[partial]** (`internal/crypto`, `internal/cap`)

**Implemented:** symmetric authenticated encryption — `NewKey`, `Seal`, `Open`
(AES-256-GCM, `internal/crypto`), used by the pipeline for per-chunk encryption; and a
first cut of **cap delivery** (`internal/cap`): ML-KEM-768 recipient identities
(NIST FIPS 203, `crypto/mlkem`) with `Wrap`/`Unwrap` (a KEM-DEM: ML-KEM encapsulation
keying an AES-256-GCM seal), which `revika-ctl share` uses to encrypt a
file's read-cap (its serialized manifest) to a recipient's public key. **Still
planned:** the derivation chain (write-cap → read-cap → verify-cap), signing keys for
mutable root pointers, and a compact string form for caps.

The **capability** ("cap") is how access is named and delegated:

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

- **Revocation** via key rotation + indirection: put per-file/per-directory keys behind a
  small key-holder blob the User re-wraps; revoking future reads = rotating that blob.
- **Conditions / least privilege** via the existing **write-cap → read-cap → verify-cap**
  derivation chain (§3.5): mint narrow read-caps per subtree instead of one master cap.
- **Delivery** stays the ML-KEM-768 `Wrap`/`Unwrap` already implemented.

PRE is therefore **parked**, not pursued: revisit only if a standardized, stdlib-grade
lattice PRE appears *and* a variant exists that avoids a trusted PKG and can operate at the
cap layer rather than on content-addressed shards. Tracked in §10.

### 3.6 Filesystem / metadata layer — **[partial]**

- **File manifest** — **[partial]**. `pipeline.FileManifest` exists today as an in-memory
  value: the original file name, ordered `ChunkRef`s (per-chunk key + ordered shard IDs),
  the `Config`, and total size. The name lets `get` restore the file under its original
  name without being told it. Still **[planned]**: encrypting it, storing it as an immutable
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

- **Provider records — [implemented]:** `shardID → peers` (who holds a given shard),
  via `go-libp2p-kad-dht` on a private `/revika` protocol prefix (so revika runs its own
  Kademlia network — protocol `/revika/kad/1.0.0` — not a corner of the public IPFS DHT).
  Nodes also advertise themselves under the `revika/storage/1.0.0` rendezvous namespace so
  clients discover storage nodes with no central registry. See `internal/net/dht.go`
  (`Discovery`) and `placement.go` (`DHTStore`/`PlacementStore`).
- **Mutable records — [planned]:** `user-pubkey → signed root pointer` (IPNS-like).

## 7. Repo layout (`✓` = implemented, rest planned)

```
cmd/
  revika-node/     ✓ headless Node server binary
  revika-ctl/      ✓ User client CLI (keygen/put/get/share)
  revika-daemon/     # User background daemon (+ optional embedded node)  (planned)
internal/
  store/     ✓ content-addressed blob store (Mem + Disk); leases/quotas/GC TBD
  crypto/    ✓ AES-256-GCM AEAD; key derivation, signing TBD
  erasure/   ✓ Reed–Solomon encode/decode
  chunk/     ✓ fixed-size chunking (CDC planned)
  pipeline/  ✓ StoreFile/LoadFile + FileManifest (in-memory)
  repair/    ✓ availability probes + shard regeneration (local store)
  net/       ✓ libp2p host, protocol IDs, shard/probe handlers, NetStore client,
             Kademlia DHT (Discovery: bootstrap/provider records/node advertise),
             DHTStore + PlacementStore (discovery-backed store.Store's)
  cap/       ✓ ML-KEM-768 capability wrapping (Wrap/Unwrap, FIPS 203) for sharing read-caps
  manifest/    # file/dir manifest & capability types + serialization     (planned)
  placement/   # richer node selection & redundancy policy (v1 round-robin
               # lives in internal/net for now)                            (planned)
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
| P2P / transport / discovery | `github.com/libp2p/go-libp2p` (TCP+QUIC, Noise/TLS, mDNS) | in use |
| DHT discovery / provider records | `github.com/libp2p/go-libp2p-kad-dht` (`/revika` prefix) | in use |
| Cap wrapping   | stdlib `crypto/mlkem` (ML-KEM-768, FIPS 203) + AES-256-GCM DEM | in use |

Planned as later layers land:

| Concern            | Library |
|--------------------|---------|
| Signing / KDF | `crypto/ed25519` (root pointers), `golang.org/x/crypto/hkdf` |
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
4. ⬜ **Metadata + mutable root.** Serialize/encrypt manifests, encrypted directories,
   signed root pointers.
5. 🟡 **Sharing** (in progress). Cap *delivery* is implemented (`internal/cap`:
   `Wrap`/`Unwrap` to a recipient's ML-KEM-768 key) and driven by `revika-ctl share` /
   `get -cap`. **Still open:** the write-cap → read-cap → verify-cap derivation chain
   and signing keys for mutable objects.
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
  string form for caps); where `FileManifest` finally lives.
- How User identity keys relate to libp2p peer identity keys.
- Placement policy details: diversity signals available in a libp2p network, reputation
  inputs, and repair thresholds/cadence.
- Lease durations and garbage-collection policy on nodes.
- How multi-device access for a single User shares the signing key (or delegates via
  additional caps).
- Fine-grained / revocable sharing beyond handing over a read-cap. **Proxy re-encryption
  (incl. IB-CPRE) is rejected for v1** (§3.5: breaks content-addressing/repair, needs a
  trusted PKG, and has no PQC-class standardized scheme); the near-term path is revocation
  via key rotation + the read-cap/verify-cap derivation chain. Revisit PRE only if a
  stdlib-grade lattice PRE without a trusted authority appears.
