# CLAUDE.md

Guidance for Claude Code working in this repo. These instructions override default behavior.

## What revika is

A decentralized, distributed, end-to-end encrypted storage system — a self-hosted
Dropbox/Drive over a peer-to-peer network. Files are split, encrypted, and spread across
independent nodes so no single node holds a whole file and the system tolerates node loss.
See [Architecture.md](Architecture.md) for full detail; keep it and this file updated as the
code changes.

**Roles:** *User* holds the keys and stores/retrieves/shares data; *Node* is a dumb server
that stores ciphertext shards. One machine can be both.

## Guiding principle

**Nodes are dumb, untrusted blob stores.** They only ever see encrypted, erasure-coded shards
addressed by content hash. All intelligence (chunking, encryption, keys, sharing) lives on the
User side — a node is trusted for *availability*, never *confidentiality*.

## Design constraints (settled — treat as fixed unless the maintainer changes them)

- **Never mention Tahoe-LAFS nor make design choices inspired by it** Always use Specifications and Architecture documents, and state-of-the-art concepts for cryptography and P2P sharing
- **Keep all READMEs in subpackages up to date**
- **All crypto must be PQC-class.** Cap wrapping = ML-KEM-768 (FIPS 203) via stdlib
  `crypto/mlkem` as a KEM-DEM with AES-256-GCM. AEAD = AES-256-GCM (stdlib; AES-256 is
  PQC-safe). Signatures stay Ed25519 (FIPS 204 ML-DSA not yet in stdlib).
- **Redundancy = erasure coding**, not replication: `k` data + `m` parity shards, any `k`
  reconstruct. Use `klauspost/reedsolomon`, don't hand-roll. Default `k=4`, `m=2`.
- **Networking = go-libp2p** (+ `go-libp2p-kad-dht`). Use it for discovery (Kademlia DHT on a
  private `/revika` prefix for WAN, mDNS for LAN), NAT traversal, and transport. Build revika
  protocols as versioned libp2p stream protocols; don't roll a bespoke wire protocol.
- **Everything is encrypted client-side** before shards leave the machine.
- **Sharing = wrapping/sharing keys**, never copying plaintext. A read-capability = manifest
  location + decryption key, wrapped with the recipient's public key.
- **Repair is mandatory** — erasure coding without repair only delays data loss. Repair operates
  on ciphertext only (no decryption key), relying on `erasure.Encode` being deterministic so
  regenerated shards reproduce their content addresses.

## Toolchain & conventions

- **Formatting** prefer spaces over tabulation
- **Module path is `revika`** (bare).
- **Go 1.26** (`go 1.26` in `go.mod`). System `go` is older; leave `GOTOOLCHAIN` at its default
  (`auto`) so 1.26 auto-downloads on first build.
- **Stay cgo-free / pure Go** — e.g. SQLite via `modernc.org/sqlite`, crypto from stdlib. Prefer
  stdlib over external crypto deps; isolate swappable choices behind small interfaces.
- Match surrounding code style, naming, and comment density.
- **Sudo commands:** don't run them — ask the maintainer to run in a separate terminal and paste
  the output.

## Commands

```bash
go build ./...            # build everything
go test ./...             # run all tests (use -race)
go test ./path/to/pkg     # test a single package
go test -run TestName ./path/to/pkg
go vet ./...
go run ./cmd/revika-node  # Node daemon (-data -listen -mdns -dht -bootstrap -advertise
                          #   -quota -lease-ttl -gc-interval -gc-expired-leases -repair
                          #   -repair-interval -metrics -v)
go run ./cmd/revika-ctl   # User client: keygen | put | get | delete | share (see -h)
```

`keygen` writes two keypairs: `<prefix>.key/.pub` (ML-KEM-768, receiving shares) and
`<prefix>.sign.key/.sign.pub` (Ed25519, the storage owner identity). `put`/`delete` sign with
`-signkey` (default `.revika/keys/user.sign.key`).

Runtime state lives under `.revika/` (git-ignored): node shares, SQLite ledger, keys, mock store.

## Repo layout

```
cmd/revika-node/   headless Node daemon        cmd/revika-daemon/  (planned)
cmd/revika-ctl/    User client CLI
internal/
  store/     content-addressed blob store (Mem + Disk)
  crypto/    AES-256-GCM AEAD
  erasure/   Reed–Solomon encode/decode
  chunk/     fixed-size chunking (CDC planned)
  stripe/    non-confidential erasure metadata (Descriptor) + signed repair grant
  pipeline/  StoreFile/LoadFile + FileManifest (in-memory; serialized to local JSON by revika-ctl)
  repair/    availability probes + shard regeneration
  net/       libp2p host, shard/probe protocols, NetStore, ledger-gated Server, DHT
             (Discovery), DHTStore + PlacementStore + RepairStore, signed auth tokens
  cap/       ML-KEM-768 cap wrapping (Wrap/Unwrap) + Ed25519 signing identity
  ledger/    per-node SQLite ownership/lease/quota + stripe index
  manifest/  on-disk/on-wire manifest (planned)
  placement/ node selection policy (round-robin cut lives in net/ for now; richer policy planned)
  sync/      daemon folder-watch + reconcile (planned)
```

Terms: **shard/share** = an erasure-coded encrypted piece of a file; **ledger** = node-side
SQLite ownership/lease/quota index (`.revika/ledger/ledger.db`), *not* a blockchain; **keys** =
User ML-KEM + User Ed25519 signing + node libp2p identity; **mock store** = in-memory backend
for testing before the network layer.

## Build order (PoC — walk before run)

Prove the core loop first (chunk → encrypt → erasure-code → distribute → retrieve → repair)
against the mock store, then swap the mock for real libp2p nodes. Sharing and the sync daemon
come after. Defer payment/incentive layers, global consensus, and Byzantine reputation.
