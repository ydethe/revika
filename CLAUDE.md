# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**Early — the offline core loop plus the networked Node role are implemented; the
User daemon, manifests-on-disk, and sharing are not.** Build-order steps 1–3 exist
and pass `go test -race`: the offline pipeline (chunk → encrypt → erasure-code →
store → retrieve → **repair**) *and* the libp2p network layer that puts the shard
store on the wire, with a runnable `revika-node` daemon (Node role). There is as yet
**no User daemon (`revika-daemon`), no DHT provider records, no manifests-on-disk, no
sharing, no sync engine** — everything above the network/repair layer is still the
*intended* design described below. Verify against the actual tree before relying on
any path or type not listed as implemented, and update this file as more lands.

Implemented packages (see [Architecture.md](Architecture.md) for detail):

| Package | Role |
|---------|------|
| `internal/store`   | content-addressed blob store: `Store` iface + `MemStore` + `DiskStore` |
| `internal/crypto`  | AES-256-GCM AEAD (stdlib): `NewKey`/`Seal`/`Open` |
| `internal/erasure` | Reed–Solomon `Encode`/`Decode` (`klauspost/reedsolomon`) |
| `internal/chunk`   | fixed-size chunker (`iter.Seq2`); CDC is a planned upgrade |
| `internal/pipeline`| `StoreFile`/`LoadFile` + `FileManifest`; wires the four above |
| `internal/repair`  | `Check` (probe) + `Repair` (regenerate missing shards) |
| `internal/net`     | libp2p host + `/revika/shard` & `/revika/probe` protocols; `Server` (Node) + `NetStore` (a `store.Store` over the wire) |
| `cmd/revika-node`  | headless Node daemon: serves shards from a `DiskStore`, persistent libp2p identity, mDNS |

### Toolchain & key decisions made during implementation

- **`go.mod` module path is `revika`** (bare). Rename via `go mod edit -module <path>`
  plus an import rewrite if a `github.com/...` path is wanted.
- **Go 1.26** (`go 1.26` in `go.mod`). The system `go` is older, so `GOTOOLCHAIN=auto`
  auto-downloads 1.26 on first build — leave `GOTOOLCHAIN` at its default.
- **AEAD = AES-256-GCM from the standard library**, not XChaCha20, to avoid an external
  crypto dependency. Isolated behind `crypto.Seal`/`Open`, so it is swappable.
- **Reed–Solomon = `klauspost/reedsolomon` v1.14.1.**
- **Chunking is fixed-size** for now (`chunk.DefaultSize` = 4 MiB); content-defined
  chunking can replace it behind the same iterator contract.
- **Default erasure = `k=4`, `m=2`** (`pipeline.DefaultConfig`); not yet tuned.
- **Repair needs no decryption key** — it operates on ciphertext shards and relies on
  `erasure.Encode` being deterministic, so regenerated shards reproduce their original
  content addresses and the manifest never changes.

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
- **ledger** — per-user index/accounting of what is stored where (see mutable state
  below); *not* a global blockchain.
- **keys** — User encryption keys and node identity keys (libp2p peer identity).
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
`golang.org/x/crypto` (chacha20poly1305, nacl/box, hkdf), `bbolt`/SQLite, `fsnotify`.

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
go run ./cmd/revika-node  # run the Node daemon (flags: -data, -listen, -mdns, -v)
```

Runtime state is written under `.revika/` and is git-ignored. Compiled binaries
(`/revika`, `/revika-node`, `/revika-daemon`) are also git-ignored — adjust these
names in `.gitignore` if the final binary names differ.

### Repo layout (`✓` = implemented, rest planned)

```
cmd/revika-node/   ✓ headless Node daemon           cmd/revika-daemon/  (planned)
internal/
  store/     ✓ content-addressed blob store (Mem + Disk); leases/quotas TBD
  crypto/    ✓ AES-256-GCM AEAD; key derivation & capabilities TBD
  erasure/   ✓ Reed–Solomon encode/decode
  chunk/     ✓ fixed-size chunking (CDC planned)
  pipeline/  ✓ StoreFile/LoadFile + FileManifest (in-memory manifest for now)
  repair/    ✓ availability probes + shard regeneration
  net/       ✓ libp2p host, protocol IDs, shard/probe stream handlers, NetStore client
             (DHT provider records still TBD)
  manifest/    on-disk/on-wire manifest + capabilities      (planned)
  placement/   node selection & redundancy policy           (planned)
  ledger/      per-user index/accounting, root pointer       (planned)
  sync/        daemon folder-watch + reconcile (daemon only) (planned)
```

Note: `FileManifest`/`ChunkRef` currently live in `internal/pipeline` as in-memory
values. When serialization + capabilities land they are expected to move to
`internal/manifest`.

## Open questions (decide before/while implementing)

Resolved so far: module path (`revika`), AEAD (AES-256-GCM), chunking for v1 (fixed-size),
default erasure params (`k=4`, `m=2`). Still open:

- Content-defined chunking parameters, if/when CDC replaces fixed-size.
- How User identity keys relate to libp2p peer identity keys.
- Concrete cap/manifest serialization format (and where `FileManifest` finally lives).
- Whether `k`/`m` and shard sizing should vary by file size / durability target.
- Node selection policy details (diversity, reputation) and repair thresholds/cadence.
- Lease durations and node-side garbage collection.

See [Architecture.md](Architecture.md) for the reasoning behind each.
