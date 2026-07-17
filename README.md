# revika

A decentralized, distributed, end-to-end encrypted storage system — a self-hosted
Dropbox/Drive that runs over a peer-to-peer network instead of a central server. Files are
split, encrypted, and spread across many independent nodes, so no single node ever holds a
whole file (or any plaintext) and the system tolerates node loss.

Think **"RAID-6 over the internet, with client-side encryption"** — the [Tahoe-LAFS][tahoe]
model on modern P2P plumbing ([go-libp2p][libp2p]).

[tahoe]: https://tahoe-lafs.org/
[libp2p]: https://github.com/libp2p/go-libp2p

## How it works

- **Nodes are dumb, untrusted blob stores.** They only ever see encrypted,
  erasure-coded shards addressed by content hash. All intelligence — chunking, encryption,
  key management, sharing — lives on the User (client) side. A node is trusted for
  *availability*, never for *confidentiality*.
- **Everything is encrypted client-side** before it leaves the machine (AES-256-GCM, a
  fresh random key per chunk).
- **Redundancy is erasure coding, not replication.** Each chunk is split into `k` data +
  `m` parity shards (default `k=4`, `m=2`); any `k` of the `k+m` shards reconstruct it.
- **Repair is built in.** A maintenance pass probes shard availability and regenerates
  missing shards — without needing any decryption key, and without changing content
  addresses (Reed–Solomon encoding is deterministic).
- **Sharing wraps capabilities, not data.** A read-capability (manifest + decryption keys)
  is sealed to a recipient's public key. No shards are copied; nodes learn nothing.

The store path is: **chunk → encrypt → erasure-code → address by `hash(shard)` → store**.
Retrieval runs it in reverse, fetching any `k` of `n` shards.

## Roles & artifacts

- **User** — stores, retrieves, and shares data; holds the encryption keys. Drives the
  network through the `revika-ctl` client (a background daemon is planned).
- **Node** — a server (`revika-node`) that stores encrypted shards on behalf of users.
- A single machine can be both.

## Project status

This is a proof-of-concept under active development. The **offline core loop**, the
**networked Node role**, and a first cut of **client-side sharing** are implemented and
pass `go test -race`. The background User daemon, DHT-based placement/discovery, mutable
root pointers, and directories are **not** yet built. See [Architecture.md](Architecture.md)
for a layer-by-layer `[implemented]`/`[partial]`/`[planned]` breakdown and
[CLAUDE.md](CLAUDE.md) for the condensed status.

| Package | Role | Status |
|---------|------|--------|
| `internal/store`    | content-addressed blob store: `Store` iface + `MemStore` + `DiskStore` | ✓ |
| `internal/crypto`   | AES-256-GCM AEAD (stdlib): `NewKey`/`Seal`/`Open` | ✓ |
| `internal/erasure`  | Reed–Solomon `Encode`/`Decode` (`klauspost/reedsolomon`) | ✓ |
| `internal/chunk`    | fixed-size chunker (`iter.Seq2`); CDC planned | ✓ |
| `internal/pipeline` | `StoreFile`/`LoadFile` + `FileManifest` | ✓ |
| `internal/repair`   | `Check` (probe) + `Repair` (regenerate missing shards) | ✓ |
| `internal/net`      | libp2p host + `/revika/shard` & `/revika/probe` protocols; `Server` + `NetStore` | ✓ |
| `internal/cap`      | X25519 capability wrapping (`Wrap`/`Unwrap`, NaCl box) for sharing read-caps | ✓ |
| `cmd/revika-node`   | headless Node daemon (serves shards from a `DiskStore`) | ✓ |
| `cmd/revika-ctl`    | User client CLI: `keygen`/`put`/`get`/`share` | ✓ |
| `internal/{manifest,placement,ledger,sync}`, `cmd/revika-daemon` | metadata, placement, root pointer, sync daemon | planned |

## Requirements

- **Go 1.26** (declared in `go.mod`). The system `go` may be older; leave `GOTOOLCHAIN` at
  its default (`auto`) and it will fetch 1.26 on first build.

## Build & test

```bash
go build ./...          # build everything
go test ./...           # run all tests
go test -race ./...     # run the suite under the race detector
go vet ./...            # static checks
```

## Quickstart

Store a file on a node, retrieve it, and share it end-to-end encrypted.

**1. Start a node** (serves shards; prints its dialable address):

```bash
go run ./cmd/revika-node
# → Peer ID: 12D3KooW…
# → Listening on:
# →   /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW…
```

Useful flags: `-data <dir>` (state root, default `.revika`), `-listen <multiaddr>`
(repeatable), `-mdns=false` (disable LAN discovery), `-v` (debug logging).

**2. Store a file** with the client, using the node's full multiaddr:

```bash
NODE=/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW…
go run ./cmd/revika-ctl put -node "$NODE" ./myfile.txt
# writes ./myfile.txt.rvk.json — the manifest (its read-capability; keep it secret)
```

**3. Retrieve it** from the manifest:

```bash
go run ./cmd/revika-ctl get -node "$NODE" -manifest ./myfile.txt.rvk.json -o ./out.txt
```

**4. Share it** end-to-end encrypted. The recipient generates an identity and gives you
their public key; you wrap the manifest to it:

```bash
# recipient:
go run ./cmd/revika-ctl keygen -key bob            # writes bob.key (private) + bob.pub (public)

# you (sender): seal the manifest so only bob can open it
go run ./cmd/revika-ctl share -manifest ./myfile.txt.rvk.json -to @bob.pub
# → writes ./myfile.txt.rvk.json.cap

# recipient: unwrap the cap with their private key and fetch the file
go run ./cmd/revika-ctl get -node "$NODE" -cap ./myfile.txt.rvk.json.cap -key bob.key -o ./bob-out.txt
```

`-to` accepts a literal base64 public key or `@file`. Run any command with `-h`, or
`revika-ctl help`, for the full flag list.

> **Note:** the manifest holds the file's decryption keys. Keep it secret, or hand it out
> only via `share` wrapped to a specific recipient. Nodes never see it.

## Architecture

Layers, bottom to top: **go-libp2p network → Node blob store → placement/repair → encoding
pipeline (chunk → encrypt → erasure-code) → capability & crypto → filesystem/metadata → sync
engine (daemon only)**.

libp2p stream protocols (versioned IDs): `/revika/shard/1.0.0` (PUT/GET/HAS/DELETE) and
`/revika/probe/1.0.0` (proof-of-possession for repair). DHT provider records and signed
root pointers are planned.

Full detail — including the mutable-state-without-consensus design, the capability
derivation chain, the threat model, and the build order — is in
[Architecture.md](Architecture.md).

## Key libraries

| Concern | Library |
|---------|---------|
| Erasure coding | [`klauspost/reedsolomon`](https://github.com/klauspost/reedsolomon) v1.14.1 |
| Symmetric AEAD | stdlib `crypto/aes` + `crypto/cipher` (AES-256-GCM) |
| Content addressing | stdlib `crypto/sha256` |
| P2P transport & discovery | [`libp2p/go-libp2p`](https://github.com/libp2p/go-libp2p) (TCP+QUIC, Noise/TLS, mDNS) |
| Capability wrapping | `golang.org/x/crypto/nacl/box` + `curve25519` (X25519 anonymous seal) |

## Layout

```
cmd/
  revika-node/     ✓ headless Node server binary
  revika-ctl/      ✓ User client CLI (keygen/put/get/share)
  revika-daemon/     background User daemon (planned)
internal/
  store/     ✓ content-addressed blob store (Mem + Disk)
  crypto/    ✓ AES-256-GCM AEAD
  erasure/   ✓ Reed–Solomon encode/decode
  chunk/     ✓ fixed-size chunking (CDC planned)
  pipeline/  ✓ StoreFile/LoadFile + FileManifest
  repair/    ✓ availability probes + shard regeneration
  net/       ✓ libp2p host, shard/probe protocols, NetStore client
  cap/       ✓ X25519 capability wrapping for sharing read-caps
  manifest/ placement/ ledger/ sync/   (planned)
```

Runtime state is written under `.revika/` (git-ignored): node shards, identity keys, and
the mock store.
