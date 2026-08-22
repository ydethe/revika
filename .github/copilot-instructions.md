# Copilot Instructions

## Project status

**Greenfield.** As of this writing the repo contains only `.gitignore` and `.github/`
config — no Go code, no `go.mod`, no commits. Everything below is the *intended*
design, agreed with the maintainer, not yet-existing code. Verify against the actual
tree before relying on any path or type named here, and update this file as the real
architecture lands.

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
- **Documentation** always keep track of design decisions in docs/Architecture.md, and update it as the design evolves. The code should be
  self-documenting, but the architecture doc is the source of truth for design intent. In the same way, keep track of specs and reqs in docs/Specifications.md, and update it as the design evolves. The code should be self-documenting, but the specifications doc is the source of truth for design intent.
### Concepts to keep straight

The `.gitignore` reserves `.revika/` for persisted runtime state: **node shares,
ledger, keys, and a mock store**. Expected meanings:

- **shard/share** — an erasure-coded, encrypted piece of a file stored on a Node.
- **ledger** — record of what is stored where / accounting of shards and nodes.
- **keys** — User encryption keys and node identity keys (libp2p peer identity).
- **mock store** — an in-development storage backend standing in for real distributed
  storage, so components can be built/tested before the network layer is complete.

## Commands

Standard Go toolchain:

```bash
go build ./...            # build everything
go test ./...             # run all tests
go test ./path/to/pkg     # test a single package
go test -run TestName ./path/to/pkg   # run a single test
go vet ./...              # static checks
go run .                  # run (once a main package exists)
```

Runtime state is written under `.revika/` and is git-ignored. Compiled binaries
(`/revika`, `/revika-node`, `/revika-daemon`) are also git-ignored — adjust these
names in `.gitignore` if the final binary names differ.

## Open questions (decide before/while implementing)

- Module path for `go.mod` and the repo layout (e.g. `cmd/node`, `cmd/daemon`,
  `internal/...`).
- Exact crypto scheme: per-file symmetric key, key wrapping for sharing, and how User
  identity keys relate to libp2p peer identity keys.
- Whether the ledger is per-user local, gossiped, or anchored to something shared —
  and how shard placement / node selection is decided.
- Erasure-coding parameters (`k`, `m`) and shard sizing.
