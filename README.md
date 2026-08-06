# revika

A decentralized, distributed, end-to-end encrypted storage system — a self-hosted
Dropbox/Drive that runs over a peer-to-peer network instead of a central server. Files are
split, encrypted, and spread across many independent nodes, so no single node ever holds a
whole file (or any plaintext) and the system tolerates node loss.

Think **"RAID-6 over the internet, with client-side encryption"** on modern P2P plumbing
([go-libp2p][libp2p]).

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
| `cmd/revika-ctl`    | User client CLI: `keygen`/`put`/`get`/`delete`/`share` | ✓ |
| `internal/{manifest,placement,ledger,sync}`, `cmd/revika-daemon` | metadata, placement, root pointer, sync daemon | planned |

## Requirements

- **Go 1.26** (declared in `go.mod`). The system `go` may be older; leave `GOTOOLCHAIN` at
  its default (`auto`) and it will fetch 1.26 on first build.

### Recommended: increase the UDP receive buffer (QUIC)

libp2p carries traffic over QUIC (UDP), which wants a large kernel receive buffer. If the
system limit is too low you'll see a one-time startup warning like:

```
failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB)
```

This is harmless — revika keeps working with the smaller buffer — but the undersized buffer
can drop packets during bursts and cap throughput on high-bandwidth, high-latency (WAN)
transfers. It has no measurable effect on small commands or LAN use, so tuning it is optional.

To silence the warning and get full QUIC throughput, raise the limits (Linux):

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

Make it persistent by adding the same two lines to `/etc/sysctl.d/99-revika.conf` (then
`sudo sysctl -p`). See the [quic-go UDP buffer notes][quic-buffers] for details and macOS
equivalents.

[quic-buffers]: https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes

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
(repeatable), `-v` (debug logging).

**2. Create your identity.** `keygen` writes an ML-KEM-768 (FIPS 203) keypair (for receiving
shared files) and an Ed25519 signing keypair — your storage *owner* identity, which authorizes
storing and removing your shards:

```bash
go run ./cmd/revika-ctl keygen        # writes .revika/keys/user.key/.pub + user.sign.key/.pub
```

Your files live in a **namespace**: one mutable root directory addressed by `rvk:` paths
(e.g. `rvk:docs/report.pdf`). The root in effect is the `-root` file (default
`$REVIKA_ROOT`, else `.revika/root.json`); your own root is mutable, a root someone shared
with you is read-only. Every `rvk:` command reaches nodes over the DHT through the
bootstrap peers saved in the workspace (set by `connect`); override per command with
`-node <ma>` to pin a single node.

**3. Store a file** into your namespace with `cp`, using the node's full multiaddr. The
store is signed with your signing key (default `.revika/keys/user.sign.key`, override with
`-signkey`), so only you can later remove it:

```bash
NODE=/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW…
go run ./cmd/revika-ctl cp -node "$NODE" ./myfile.txt rvk:docs/     # store as docs/myfile.txt
# advances .revika/root.json — your signed namespace anchor (holds read-caps; kept 0600)
```

**4. Browse and retrieve.** `ls` reads directory blobs only (no file content); `cp` the
other way pulls the file:

```bash
go run ./cmd/revika-ctl ls -node "$NODE" rvk:docs           # list docs/ (add -l for detail)
go run ./cmd/revika-ctl cp -node "$NODE" rvk:docs/myfile.txt ./out.txt
```

**5. Remove it** when you are done. Only the signing key that stored a shard can release it;
a node frees a shard's bytes only once its last owner leaves, so this never affects another
user's copy of data you shared:

```bash
go run ./cmd/revika-ctl rm -node "$NODE" rvk:docs/myfile.txt
```

**6. Share it** end-to-end encrypted. The recipient generates an identity and gives you
their public key; `share` seals a **shared root** anchored at the path — a signed
`RootPointer` wrapped to their key (never a bearer token). Resolving the path walks the
tree, so `share` needs a backend:

```bash
# recipient:
go run ./cmd/revika-ctl keygen -key bob            # writes bob.key (private) + bob.pub (public)

# you (sender): seal a share of one file (or a whole subtree) so only bob can open it
go run ./cmd/revika-ctl share -node "$NODE" -to @bob.pub -o ./shared.root.json rvk:docs/myfile.txt

# recipient: open the sealed root with their key and browse / retrieve it
go run ./cmd/revika-ctl ls -node "$NODE" -root ./shared.root.json -key bob.key rvk:
go run ./cmd/revika-ctl cp -node "$NODE" -root ./shared.root.json -key bob.key rvk: ./bob-out.txt
```

`-to` accepts a literal base64 public key or `@file`. Point `share` at a subdirectory
instead (`rvk:docs`) to share a whole subtree; `ls`/`cp` auto-detect file vs. subtree from
the cap's `Kind`. Run any command with `-h`, or `revika-ctl help`, for the full flag list.

> **Note:** the root pointer (and any sealed shared root) holds the files' decryption keys.
> Keep it secret, or hand it out only via `share` wrapped to a specific recipient. Nodes
> never see it.

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

## Security

The threat model is catalogued under [`security/`](security/README.md): one folder per
attack scenario, each with a stable identifier (`N-…` for nodes, `C-…` for clients) and a
`README.md` describing it. The flat source document lives at
[`security/Security.md`](security/Security.md); it deliberately lists threats only, no
defences.

## Key libraries

| Concern | Library |
|---------|---------|
| Erasure coding | [`klauspost/reedsolomon`](https://github.com/klauspost/reedsolomon) v1.14.1 |
| Symmetric AEAD | stdlib `crypto/aes` + `crypto/cipher` (AES-256-GCM) |
| Content addressing | stdlib `crypto/sha256` |
| P2P transport & discovery | [`libp2p/go-libp2p`](https://github.com/libp2p/go-libp2p) (TCP+QUIC, Noise/TLS, Kademlia DHT) |
| Capability wrapping | `golang.org/x/crypto/nacl/box` + `curve25519` (X25519 anonymous seal) |

## Layout

```
cmd/
  revika-node/     ✓ headless Node server binary
  revika-ctl/      ✓ User client CLI (keygen/put/get/delete/share)
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
security/          threat model: one folder per attack scenario + Security.md source
```

Runtime state is written under `.revika/` (git-ignored): node shards, identity keys, and
the mock store.
