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
- **Nodes may defend their own availability.** "Dumb" means dumb about *content*, not defenceless:
  an operator-run node is allowed local, operator-controlled anti-DoS/anti-DDoS defences that never
  decrypt or interpret a shard — they act only on connection/identity/volume metadata. Sanctioned
  levers: libp2p `ResourceManager` + `ConnManager` limits, a `ConnectionGater` with a static
  peer/subnet blocklist (and optional allowlist), and per-peer / per-owner rate limiting keyed on
  the Ed25519 owner pubkey. Existing per-owner quota + leases stay the *storage* cap; these add a
  *flow/connection* cap. The rcmgr/connmgr/gater + static blocklist live in
  `internal/net/defense.go` (wired via `HostConfig.Defense`); write-verb rate limiting is still
  TODO. Note ban-by-identity is weak while identities are free to mint — global anti-Sybil,
  reputation, and economic layers remain deferred (see Architecture.md §5).

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
go run ./cmd/revika-node  # Node daemon (-data -listen -public-ip -mdns -dht -bootstrap
                          #   -advertise -quota -lease-ttl -gc-interval -gc-expired-leases
                          #   -repair -repair-interval -metrics -blocklist -conn-low
                          #   -conn-high -conn-grace -pow-difficulty -pow-puzzle -v)
go run ./cmd/revika-ctl   # User client: keygen | cp | ls | rm | share | node (see -h)
```

The client is **namespace-centric**: a User's files live under one mutable root
directory addressed by `rvk:` paths (e.g. `rvk:docs/report.pdf`), anchored by a
signed `manifest.RootPointer` persisted via `provider.FileRootStore` (default
`.revika/root.json`, overridable with `-root`/`$REVIKA_ROOT`). `cp` writes/reads
scp-style (`cp file rvk:docs/` stores, `cp rvk:docs/file .` retrieves); `ls`
browses (dir blobs only, `-l`/`-R`); `rm` grafts-out a subtree and releases its
shards; `share rvk:PATH -to <key>` seals a `RootPointer` anchored at that subtree
to the recipient's ML-KEM key (a *sealed shared root* file the recipient uses as
`-root … -key <priv>` — never a bearer token); `node` lists DHT-discovered nodes.
Own root = mutable; a shared root = read-only.

`keygen` writes two keypairs: `<prefix>.key/.pub` (ML-KEM-768, receiving shares) and
`<prefix>.sign.key/.sign.pub` (Ed25519, the storage owner identity). The signing key is
*self-certifying*: it is ground via proof-of-work (`-pow-difficulty`/`-pow-puzzle`, default
argon2id@12) until its pubkey hashes under the target, so re-minting a banned identity costs
CPU, not milliseconds (`internal/cap/pow.go`). Nodes admit writes only from owners meeting
their own `-pow-difficulty` (default 0 = off), so client and node must use a matching puzzle
and the client's difficulty must be ≥ the node's. `cp` (store)/`rm`/`share` sign with
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
  compress/  optional pre-encryption DEFLATE stage (per-chunk, skipped when it doesn't help)
  chunk/     fixed-size chunking (CDC planned)
  stripe/    non-confidential erasure metadata (Descriptor) + signed repair grant
  pipeline/  StoreFile/LoadFile + FileManifest (in-memory; serialized to local JSON by revika-ctl)
  repair/    availability probes + shard regeneration
  net/       libp2p host, shard/probe protocols, NetStore, ledger-gated Server, DHT
             (Discovery), DHTStore + PlacementStore + RepairStore, signed auth tokens
  cap/       ML-KEM-768 cap wrapping (Wrap/Unwrap) + Ed25519 signing identity
  ledger/    per-node SQLite ownership/lease/quota + stripe index
  manifest/  cap-addressed encrypted file/dir blobs = Merkle DAG (ReadCap, DirManifest,
             COW Graft, signed RootPointer); reuses pipeline blobs + cap wrapping
  fsmeta/    capture/restore live-file attributes ⇄ pipeline.Metadata (Linux + portable split);
             shared by revika-ctl and provider
  provider/  framework-neutral OS filesystem-integration API (Provider iface) mapping macOS File
             Provider / Windows Cloud Filter / Linux GVfs; Manifest impl over the manifest DAG with
             stable ItemIDs, DAG-diff change enumeration, and a RootStore seam for the (planned) DHT
             root publish
  placement/ node selection policy — pluggable Selector (round-robin, smooth weighted
             round-robin) + failure-domain Spread; wired into net.PlacementStore
  sync/      poll-based folder-watch daemon + three-way reconcile engine over a
             provider.Provider (bidirectional, conflict policies)
```

Terms: **shard/share** = an erasure-coded encrypted piece of a file; **ledger** = node-side
SQLite ownership/lease/quota index (`.revika/ledger/ledger.db`), *not* a blockchain; **keys** =
User ML-KEM + User Ed25519 signing + node libp2p identity; **mock store** = in-memory backend
for testing before the network layer.

## Build order (PoC — walk before run)

Prove the core loop first (chunk → encrypt → erasure-code → distribute → retrieve → repair)
against the mock store, then swap the mock for real libp2p nodes. Sharing and the sync daemon
come after. Defer payment/incentive layers, global consensus, and Byzantine reputation.
