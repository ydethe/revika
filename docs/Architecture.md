# Revika Architecture

## 1. System Overview

Revika is a decentralized, distributed, end-to-end encrypted storage system with three primary components:

1. **User Daemon** — Background service syncing a local folder to the network, handling file encryption/decryption, key management, and optional in-process Node service
2. **Node Server** — Standalone server storing encrypted shards and serving retrieval requests
3. **User CLI** — Testing and interactive interface for filesystem operations and network management

## 2. Core Components

### 2.1 User Daemon

- **LocalSync** — Monitors local folder (`.revika/user-data/`), detects changes, stages files for upload
- **Cryptography Engine** — Encrypts files client-side before any transmission
- **ShardClient** — Communicates with remote Nodes; requests shard uploads/downloads
- **KeyManager** — Manages user encryption keys and key wrapping for sharing
- **OptionalNodeService** — In-process Node server for users contributing storage

### 2.2 Node Server

- **ShardStore** — Persists encrypted shards locally (file-based, not database)
- **PeerManager** — Manages connections to other Nodes and Users via libp2p
- **LedgerSync** — Gossips shard placement information to other Nodes
- **RetrievalHandler** — Responds to shard requests from Users

### 2.3 User CLI (Testing)

**Purpose:** Interactive shell for testing filesystem operations, sharing, and network management

**Subcommands:**
- **`cd <path>`** — Change virtual working directory within `.revika/user-data/`
- **`pwd`** — Print current working directory
- **`ls [-la]`** — List files/directories at current or specified path
- **`cp <src> <dst>`** — Copy file locally (staged for upload)
- **`rm <path>`** — Delete file/directory (staged for deletion)
- **`share <file> <recipient_id>`** — Wrap per-file key and send to recipient
- **`revoke <file> <recipient_id>`** — Revoke recipient's access to file
- **`connect <network_type>`** — Join network (Public, Hybrid, or Private)
  - **Public** — Open DHT, join global IPFS-like network; anyone can discover nodes
  - **Hybrid** — DHT with allowlist; known peers only, bootstrap from trusted nodes
  - **Private** — No DHT; manual peer configuration; only pre-configured peers

### 2.4 Shared Services

- **Ledger** — Per-user distributed record of directory trees, shards, and access grants
- **DHT (libp2p Kademlia)** — Peer discovery on WAN (LAN mDNS discovery deferred post-M2)

---

## 3. Data Model

### 3.1 File & Shard Structure

- **Directory Trees:** Client operations (Daemon and CLI) work on complete directory trees as atomic units
- **File → k+m Shards** via Reed–Solomon (using `klauspost/reedsolomon`)
  - Recommended: `k=3, m=2` (any 3 of 5 shards reconstruct the file)
  - `SplitFile` uses the library's `Split` (data shards, zero-padded) followed by `Encode` (parity shards); reconstruction uses `Join` and trims back to the original file size
- **Shard metadata:** `ShardInfo` is content-addressed and minimal — `{ID, Bytes, Index}`, where `ID = SHA256(Bytes)` (hex) and `Index` is the shard's position in the `k+m` array. It deliberately does **not** carry `K`, `M`, or the original file size, because the store only persists shard bytes and any such fields would be lost on a store round-trip.
- **Reconstruction metadata is file-level, not per-shard:** `k` (data shards), `m` (parity shards), and the original unpadded file size live in `FileInfo`/the ledger. The caller reads them from there and passes them explicitly to `ReconstructFile(shards, k, m, originalSize)`, which initializes the matching Reed–Solomon decoder and trims padding.
- **Shards are encrypted** individually with a file-derived symmetric key before leaving the User machine
- **Ledger entry** maps Directory Tree ID → {Shard IDs, access grants}; shard ID acts as content address for IPFS-style retrieval

### 3.2 Encryption Scheme

- **Per-File Key:** `SHA256(user_master_key || file_hash)` → AES-256-GCM encryption
- **User Master Key:** Derived from user password/passphrase (PBKDF2, stored encrypted at rest)
- **Key Sharing:** Wrap per-file key with recipient's public key; recipient unwraps to gain access
- **Key Revocation:** Invalidate wrapped key by re-encrypting file with new per-file key; old wrapped key cannot decrypt
- **Node Perspective:** Nodes hold ciphertext; cannot decrypt without user key
- **Static decryption error policy:** `DecryptFile` and `UnwrapKey` return a single, static `"decryption failed"` error and never wrap the underlying AES-GCM authentication failure. This is deliberate — it prevents GCM internals from leaking to callers and avoids giving an attacker an oracle that distinguishes failure modes.
- **Shard-ID validation at the store boundary:** `PutShard`/`GetShard`/`DeleteShard`/`HasShard` validate the shard ID against `^[0-9a-f]{64}$` (hex SHA256) before touching the filesystem, guarding against path traversal and invalid filenames.

### 3.3 Ledger Structure (Per-User, Not Per-File)

- **Scope:** Per-user local ledger (stored in `.revika/ledger.json`); synced to trusted peer(s) for recovery
- **Organization:** Ledger groups data by directory tree; files within a tree are tracked with their shard mappings
- **File-to-Shard Mapping:** Each file has an explicit list of shard IDs that compose it; shard IDs are content addresses (IPFS-style) that the network locates automatically
- **Content:**
  ```json
  {
    "trees": {
      "tree_id_1": {
        "root_path": "Documents",
        "created": "2026-08-22T10:00:00Z",
        "files": {
          "file_id_1": {
            "path": "Documents/document.pdf",
            "content_hash": "sha256:...",
            "shards": ["shard_0", "shard_1", "shard_2"]
          },
          "file_id_2": {
            "path": "Documents/image.png",
            "content_hash": "sha256:...",
            "shards": ["shard_3", "shard_4"]
          }
        },
        "access_grants": {
          "user_456": {"since": "2026-08-22T11:00:00Z", "key_version": 1}
        }
      }
    },
    "access_revocations": {
      "user_456": {
        "tree_id_1": {"revoked_at": "2026-08-23T09:00:00Z", "key_version": 2}
      }
    }
  }
  ```

---

## 4. Networking & libp2p Protocols

### 4.1 Protocols

These protocol IDs are the canonical direct-adapter surface (V2 target and dual-stack validation path); in V1 default mode, equivalent operations are provided via the Kubo-backed adapter per the migration gates in Sections 17 and 18.

- `/revika/1.0/put-shard` — User → Node: Upload encrypted shard
- `/revika/1.0/get-shard` — User/Node → Node: Retrieve shard
- `/revika/1.0/ledger-sync` — Node ↔ Node: Gossip shard placement
- `/revika/1.0/share` — User → User: Exchange wrapped keys
- `/revika/1.0/revoke` — User → User: Notify of access revocation

### 4.2 Peer Identity

- **Node Peer ID** — libp2p-generated from Ed25519 keypair; acts as node identity
- **User Peer ID** — libp2p identity for User Daemon; separate from file encryption key
- **Peer discovery:** DHT on WAN (LAN mDNS discovery deferred post-M2)

### 4.3 Transport

- libp2p handles encryption (TLS 1.3), multiplexing, NAT traversal
- No bespoke wire protocol

### 4.4 V1 IPFS Port (Kubo-backed adapter)

Per spec IPFS001, V1 satisfies the network layer through a **Kubo-backed adapter**
rather than an in-process libp2p host. The rest of the system depends on a
capability-segregated **IPFS port** (`internal/ipfs/`) and never touches
Kubo/CID/libp2p types directly.

- **`internal/ipfs/port.go`** — the port interfaces:
  - `BlockStore` — `AddBlock` / `GetBlock` / `Pin` / `Provide` (single-block
    encrypted shards).
  - `NameService` — `PublishIPNS` / `ResolveIPNS` (mutable root pointer).
  - `PeerInfo` — `ID` / `Peers` / `Connect`.
  - `Messaging` — ledger-sync/share/revoke overlays; **deferred for V1** (defined
    for forward-compatibility, not wired).
  - `Backend` composes `BlockStore` + `NameService` + `PeerInfo`.
- **`internal/ipfs/kubo/`** — the V1 adapter. It talks to an **external Kubo
  daemon** over its RPC HTTP API via `github.com/ipfs/go-ipfs-api`. Kubo/network
  errors are wrapped as `model.ErrNetworkFailure` so consumers never see Kubo
  internals.
- **Import invariant:** ONLY `internal/ipfs/kubo` may import Kubo, `go-cid`, or
  libp2p packages. `internal/node`, `internal/daemon`, `internal/cli`, and
  `pkg/model` stay Kubo-free.
- **Operational requirement:** V1 requires a running Kubo daemon
  (`ipfs daemon`, default RPC `127.0.0.1:5001`) alongside revika. Adapter
  construction is lazy; reachability failures surface on the first
  network-touching call.

#### Shard ID ⇔ CID reconciliation

Shards are stored as a **single-block CIDv1, `raw` codec, `sha2-256`** multihash,
so the CID's multihash digest equals our existing sha2-256 shard hash
(`model.ComputeShardID`). This reconciles the Phase-1 "Shard ID = SHA256"
decision with IPFS002 (CID addressing):

- **Shard ID** stays a sha2-256 hex string — the durable *integrity* identifier.
- **CID** is the *network address* used to fetch the block from IPFS.
- `pkg/model.ShardInfo` gained a `CID` field, and a new
  `model.ShardRef{Hash, CID, Index}` carries both. Ledger `File.Shards` is now
  `[]model.ShardRef` (was `[]string`).

#### Store of record vs. content-addressed copy

`internal/store/` remains the **store of record**: nodes durably hold the
ciphertext shards they cannot read. Kubo's pinned blockstore is the
content-addressed transport/cache copy. V1 accepts ~2× disk for a simpler
design — `node.Server.StoreShard` writes to the store AND performs `AddBlock` +
`Provide` on the Kubo backend.

### 4.5 Direct libp2p path (V2, dormant)

The direct go-libp2p host and its five stream-protocol handlers
(put-shard/get-shard/ledger-sync/share/revoke) live in `internal/network/` and
are preserved as the **dormant V2 path**, gated behind the `//go:build v2direct`
tag. They are therefore excluded from `go build ./...` / `go test ./...` by
default. The protocol IDs in Section 4.1 describe this V2 surface; in V1 the
equivalent operations are provided by the Kubo adapter. Overlay protocols
(ledger-sync/share/revoke) and LAN mDNS discovery are deferred for V1.

### 4.6 Network Types (IPFS Terminology)

| Type | Discovery | Bootstrap | Use Case |
|------|-----------|-----------|----------|
| **Public** | Global DHT | Public bootstrap nodes | Open, collaborative storage |
| **Hybrid** | DHT with allowlist | Trusted bootstrap peers | Semi-open with curated nodes |
| **Private** | Manual peer config | Static peer list | Closed org/family network |

---

## 5. Module Layout (Go)

### Implementation Status

| Package | Status | Details |
|---------|--------|---------|
| **Phase 1** | | |
| `internal/crypto/` | ✅ Complete | PBKDF2, AES-256-GCM, ECIES key wrapping (285 LOC, 17 tests) |
| `internal/shard/` | ✅ Complete | Reed-Solomon k=3/m=2 (200 LOC, 13 tests) |
| `internal/store/` | ✅ Complete | File-based persistent storage (280 LOC, 14 tests) |
| `pkg/model/` | ✅ Complete | Shared types: ShardInfo, FileInfo, LedgerEntry (60 LOC) |
| **Phase 2** | | |
| `internal/ipfs/` | ✅ V1 network layer | IPFS port (`port.go`) + Kubo adapter (`kubo/`) over external Kubo RPC |
| `internal/network/` | 💤 Dormant (V2) | Direct libp2p host + 5 stream handlers, gated behind `//go:build v2direct` |
| `internal/ledger/` | ✅ Complete | Ledger read/write, sync logic (10 tests) |
| `internal/daemon/` | 🔨 Structured | IPC server, service logic (7 tests) |
| `internal/node/` | 🔨 Structured | Node server, shard handlers (5 tests) |
| `internal/cli/` | ✅ Complete | Interactive shell, command handlers (9 tests) |
| `cmd/{daemon,node,cli}/` | ✅ Complete | Entry points complete |

### Directory Structure

```
revika/
├── go.mod                          # Module: github.com/revika/revika
├── cmd/
│   ├── daemon/main.go              # User Daemon entry point ✅
│   ├── node/main.go                # Node Server entry point ✅
│   └── cli/main.go                 # User CLI entry point ✅
├── internal/
│   ├── crypto/                     # ✅ Encryption, key derivation (Phase 1)
│   ├── shard/                      # ✅ Erasure coding (Phase 1)
│   ├── store/                      # ✅ Persistent storage / store of record (Phase 1)
│   ├── ledger/                     # ✅ Ledger management (Phase 2)
│   ├── ipfs/                       # ✅ V1 IPFS port (port.go) + Kubo adapter (kubo/)
│   ├── network/                    # 💤 V2 direct libp2p (build tag: v2direct)
│   ├── daemon/                     # 🔨 Daemon service (Phase 2)
│   ├── node/                       # 🔨 Node server (Phase 2)
│   └── cli/                        # ✅ CLI shell (Phase 2)
├── pkg/
│   └── model/                      # ✅ Shared types (Phase 1)
└── docs/
    ├── Architecture.md             # This document
    └── Specifications.md           # Design requirements
```

### Test Coverage

| Phase | Package | Tests | Coverage |
|-------|---------|-------|----------|
| P1 | crypto, shard, store, model | 44 unit | >80% |
| P1 | integration (Phase 1) | 3 integration | ✅ |
| P2 | network, ledger, daemon, node, cli | 47 unit | — |
| P2 | integration (Phase 2) | 4 integration | ✅ |
| **Total** | | **98 tests** | **47 blocking** |

**Blocking Status**: Network and node packages blocked on `libp2p` modules not in `go.mod`. Run `go mod tidy && go mod download` to proceed with testing.

---

## 6. User CLI Details

### 6.1 Shell Architecture

- **Interactive REPL** — Prompts for commands (`revika> `)
- **IPC to Daemon** — CLI communicates with User Daemon via Unix socket or TCP
- **Local State** — Maintains current working directory, network config
- **Error Handling** — Graceful feedback for network failures, permission errors

### 6.1.1 CLI↔Daemon IPC

Wire format is line-delimited JSON: `model.IPCRequest` / `model.IPCResponse`
over a Unix socket (`pkg/model`).

- **Persistent connection per session.** The CLI dials once and reuses a single
  connection, caching its JSON encoder/decoder. The daemon serves **multiple
  sequential requests** over that one connection (`handleIPCConnection` loops
  decode → handle → encode until the client disconnects on `io.EOF`).
  One-request-per-connection is **not** the model.
- **Connection tracking & graceful shutdown.** The daemon tracks live
  connections and counts in-flight handlers with a `sync.WaitGroup`. On `Stop()`
  it stops accepting, force-closes every live connection (unblocking handlers
  parked on `Decode`), and waits for handlers to exit before saving the ledger
  and removing the socket — so no handler goroutine leaks.
- **Write-only retry (self-heal).** A failed request **write** retries once with
  a fresh dial (handling a stale connection the daemon already closed). A failed
  **read** is never retried, because the request may already have executed and
  commands such as `cp`/`rm`/`share`/`revoke` are not idempotent.

### 6.2 CLI Subcommand Behavior

#### `cd <path>`
```
revika> cd Documents
revika> pwd
/Documents
```
- Changes virtual working directory within synced folder
- Relative and absolute paths supported

#### `pwd`
```
revika> pwd
/Documents
```
- Prints current working directory

#### `ls [-la]`
```
revika> ls -la
-rw-r--r-- user user 5000000 2026-08-22 10:30 document.pdf
drwxr-xr-x user user    4096 2026-08-22 11:00 subfolder/
```
- Lists files/directories; `-l` = long format, `-a` = show hidden

#### `cp <src> <dst>`
```
revika> cp document.pdf backup.pdf
```
- Copies file locally; stages both for upload to network
- Supports cross-directory copies

#### `rm <path>`
```
revika> rm document.pdf
```
- Deletes file; stages deletion in ledger
- Prompts for confirmation on directories

#### `share <file> <recipient_id>`
```
revika> share document.pdf user_456
Shared document.pdf with user_456
```
- Wraps per-file key with recipient's public key
- Sends wrapped key via network protocol
- Updates ledger to reflect sharing

#### `revoke <file> <recipient_id>`
```
revika> revoke document.pdf user_456
Revoked access to document.pdf from user_456
```
- Marks access as revoked in ledger
- Re-encrypts file with new per-file key on next sync
- Recipient's old wrapped key cannot decrypt new version
- No data deletion from nodes required

#### `connect <network_type>`
```
revika> connect Public
Connecting to Public network...
Connected. Peer ID: QmXxxx...
Discovered 12 peers on DHT

revika> connect Hybrid
Enter bootstrap peers (comma-separated): node1.example.com, node2.example.com
Connecting to Hybrid network...
Connected. Peer ID: QmYyyy...
Discovered 3 trusted peers

revika> connect Private
Loading private peer list from .revika/peers.json...
Connecting to Private network...
Connected. Peer ID: QmZzzz...
Connected to 2 known peers
```
- Initiates network connection with specified type
- Public: Global DHT discovery
- Hybrid: DHT with allowlist + manual bootstrap
- Private: Static peer configuration only

### 6.3 CLI Error Handling

- Network unavailable: "Network error: unable to connect to Daemon"
- File not found: "Error: path not found"
- Permission denied: "Error: access denied to shared_file.pdf"
- Share failure: "Error: recipient not online; wrapped key queued for delivery"
- Revoke failure: "Error: unable to revoke access; ledger sync pending"

---

## 7. Storage Backend

**Phase 1 (Greenfield):** File-based mock store under `.revika/node-store/`
- Each shard = one file: `shard_{shard_id}.bin`
- Metadata: `ledger.json` per node

**Future:** Pluggable interface for RocksDB, S3, etc.

---

## 8. File Upload Flow (Directory Tree)

1. User places files in `.revika/user-data/Documents/` (or uses CLI `cp` command)
2. Daemon detects changes in directory tree → reads all files
3. Daemon encrypts files with AES-256-GCM (per-file keys derived from master key)
4. Daemon splits each file into **k=3, m=2 shards** (5 shards total per file)
5. Daemon selects 3–5 Nodes (via DHT lookup, node reputation)
6. Daemon uploads each shard via the active network adapter (`/revika/1.0/put-shard` in direct-adapter mode)
7. Each Node acknowledges; Daemon updates local ledger with tree-level entry
8. Daemon may replicate shards to additional nodes for redundancy

---

## 9. File Download & Reconstruction

1. User requests files from directory tree
2. Daemon looks up tree in ledger → finds k=3 shard locations per file
3. Daemon fetches shards from different Nodes (with fallback to parity shards if needed)
4. Daemon uses Reed–Solomon to reconstruct ciphertext for each file
5. Daemon decrypts with file key → writes plaintext to `.revika/user-data/`

---

## 10. Shard Placement & Redundancy

- **Shard Addressing:** Shard IDs serve as content addresses (IPFS-style); network locates peers holding shards automatically
- **Initial placement:** k shards per file → uploaded to network via shard ID; network replication handles distribution
- **Replication:** m parity shards also uploaded via shard ID; network redundancy maintained through natural content distribution
- **Node failure:** If peers go offline, other peers serving the same shard ID continue serving; new peers can join
- **Ledger tracking:** Ledger maintains only shard IDs per file; peer/node locations are managed by the DHT/IPFS layer
- **Tree-level tracking:** Ledger groups all shard IDs for a directory tree together

---

## 11. Sharing & Access Control

### 11.1 Granting Access

1. User A generates **per-file symmetric key** for File X
2. User A wraps key with User B's public key → **wrapped key**
3. User A sends wrapped key to User B (via `/revika/1.0/share`)
4. User B unwraps key with their private key
5. User B can now decrypt shards for File X
6. Ledger entry marks File X as "shared with User B"

### 11.2 Revoking Access

1. User A initiates revoke via `revoke <file> <user_b>`
2. Daemon marks revocation in ledger
3. On next file sync, Daemon re-encrypts file with new per-file key
4. Daemon re-uploads new shards to Nodes
5. Daemon broadcasts revocation via `/revika/1.0/revoke` protocol
6. User B's old wrapped key is now invalid (cannot decrypt new version)
7. **No data deletion needed** — cryptographic enforcement only

---

## 12. Deployment Models

### Model 1: User-Only
- Run User Daemon (no in-process Node)
- Run User CLI for testing/interaction
- Shards stored on trusted remote Nodes

### Model 2: User + Node (Contributor)
- Run User Daemon with in-process Node
- Run User CLI
- Contribute local storage; earn reputation or incentive

### Model 3: Dedicated Node
- Run Node Server headless (no User Daemon)
- Operator manually configured; serves multiple Users

---

## 13. Error Handling & Resilience

- **Node unavailability:** Daemon still works if ≥k shards reachable
- **Shard corruption:** Reed–Solomon parity enables recovery
- **Network partitions:** Users work offline; ledger syncs when network restores
- **Key loss:** User can recover from key backup (if kept separately)
- **CLI disconnection:** CLI reuses a persistent IPC connection and self-heals a stale one by re-dialing once on a failed write; read failures are surfaced (not retried) because non-idempotent commands may already have executed
- **Partial revocation failure:** Revocation persists in ledger; re-sync on network recovery

---

## 14. Design Decisions

| Question | Decision |
|----------|----------|
| Module path | `github.com/revika/revika` |
| Crypto scheme | Per-file AES-256-GCM; key wrapping for sharing; PBKDF2 for password derivation |
| Ledger scope | Per-user local + backup to trusted peer(s) **organized per directory tree, NOT per file** |
| Ledger granularity | Directory trees as the primary unit (not individual files) |
| Erasure params | k=3, m=2 (any 3 of 5 shards) |
| Shard sizing | Derived: file is `Split` into `k` equal, zero-padded data shards (no separately tunable shard size in Phase 1) |
| Network types | Public (DHT), Hybrid (DHT + allowlist), Private (manual peers) |
| CLI testing | REPL shell with subcommands for full system testing |
| Access revocation | Cryptographic invalidation via re-encryption; no data deletion required |
| Client scope | Both Daemon and CLI handle complete directory trees as operational units |

---

## 15. Next Steps

1. **Finalize module path** (go.mod)
2. **Implement Phase 1:** `crypto/`, `shard/`, `store/` packages
3. **Implement Phase 2:** `network/` (libp2p protocols), `ledger/`
4. **Implement Phase 3:** `daemon/`, `node/`, and `cli/` binaries

---

## 16. Hexagonal Boundaries & Anti-Corruption Adapters

Revika shall enforce a hexagonal architecture so core storage/crypto/ledger logic remains independent from transport and third-party protocol stacks.

### 16.1 Boundary Principles

- **Core domain inwards only:** `internal/crypto`, `internal/shard`, `internal/ledger`, and domain orchestration in `internal/daemon`/`internal/node` shall not import adapter-specific protocol packages.
- **Ports over SDK types:** Core-facing interfaces shall use revika-native IDs, request/response structs, and canonical errors; adapter-native types (Kubo, raw libp2p, IPFS blocks) shall be translated at the edge.
- **Deterministic behavior:** Given identical inputs, Core operations shall produce equivalent ledger effects regardless of the selected network adapter.
- **Explicit adapter selection:** Runtime configuration shall select adapter mode (`kubo`, `direct`, `dual-read`) without changing Core logic paths.

### 16.2 Anti-Corruption Adapter Guidance

- **Inbound translation:** Adapter handlers shall validate and normalize peer/network payloads before invoking Core ports.
- **Outbound translation:** Core responses/errors shall be converted to adapter protocol responses without leaking internal implementation details.
- **No type leakage:** Adapter-specific identifiers shall never be persisted directly in the ledger without normalization into revika canonical fields.
- **Contract tests required:** Each adapter shall satisfy the same interoperability contract test suite before being eligible as default.

---

## 17. Release Roadmap (V1 -> V2)

### 17.1 Scope of V1 and V2

- **V1 target:** IPFS compliance and production readiness through a Kubo-backed network adapter.
- **V2 target:** Direct libp2p/IPFS-compatible adapter as default, with Kubo adapter retained as compatibility fallback until deprecation criteria are met.

### 17.2 Milestones M0..M8

| Milestone | Stage | Goal | Objective Exit Criteria | Implementation Status |
|----------|-------|------|-------------------------|-----------------------|
| **M0** | Foundation | Freeze port surface and canonical model contracts | Core <-> Network port definitions documented; canonical error set frozen; architecture decision record approved. | Done |
| **M1** | Core Baseline | Complete local crypto/shard/store/ledger pipeline | Upload/download/reconstruct/share/revoke flows pass unit + integration tests locally without network dependency. | Done |
| **M2** | V1 Build | Kubo adapter integration | Kubo adapter passes adapter contract tests for put/get/discover/publish/resolve; no Core package imports from Kubo SDK. | Not started |
| **M3** | V1 Alpha | Dual-stack read path introduced | `dual-read` mode functional: writes through Kubo, and optional read fallback to direct is available behind configuration; migration telemetry emitted. | Not started |
| **M4** | V1 GA | Kubo-first production release | Public/Hybrid/Private network modes validated; IPFS interoperability tests green via Kubo; operational runbook and rollback validated. | Not started |
| **M5** | V2 Build | Direct adapter feature parity | Direct adapter implements all mandatory Core ports and canonical errors; parity tests vs Kubo produce equivalent ledger outcomes. | Not started |
| **M6** | V2 Beta | Dual-stack migration hardening | Checkpoints A..D complete; mixed-peer clusters validated; no data-format divergence in manifests or root pointers. | Not started |
| **M7** | V2 Readiness | Interoperability gate | Direct adapter passes IPFS interoperability contract suite end-to-end; failure budget/SLO checks met for reliability/performance/security. | Not started |
| **M8** | V2 GA | Default switch to direct adapter | Default mode switched to direct; Kubo retained as compatibility fallback; checkpoint E complete with verified rollback path. | Not started |

---

## 18. Dual-Stack Migration Checkpoints (A..E)

Migration shall proceed through five gated checkpoints to move from V1 (Kubo default) to V2 (direct default).

| Checkpoint | Purpose | Compatibility Rules |
|-----------|---------|---------------------|
| **A. Port Freeze** | Freeze Core<->Network interface and canonical errors | Both adapters shall implement identical method signatures and canonical error mapping; no adapter-specific error strings propagated to Core. |
| **B. Data Format Lock** | Freeze shared data contracts | Manifest/root pointer schema version shall be identical across adapters; IDs/CIDs and hash normalization rules shall match. |
| **C. Dual Read / Single Write** | Safe mixed operation | Writes shall use one configured primary adapter; reads shall attempt primary then secondary when enabled; write acknowledgements shall include adapter provenance for debugging only (not ledger semantics). |
| **D. Mixed-Cluster Validation** | Validate interoperability under heterogeneous peers | Cluster tests shall include Kubo-only, direct-only, and mixed nodes; retrieval and revocation behavior shall remain semantically equivalent. |
| **E. Default Switch + Rollback** | Make direct adapter default safely | Direct becomes default only after M7 criteria pass; rollback to Kubo shall be a config change with no ledger migration required. |

---

## 19. Core <-> Network Interface Surface (Ports)

### 19.1 Port Surface

The Core shall depend on the following logical port capabilities (exact Go signatures may evolve without changing semantics):

- **`PutShard(ctx, ownerID, shardID, ciphertext, metadata) -> Receipt`**
- **`GetShard(ctx, ownerID, shardID) -> ciphertext`**
- **`HasShard(ctx, ownerID, shardID) -> bool`**
- **`AnnounceShard(ctx, shardID, locations) -> ack`**
- **`FindShardProviders(ctx, shardID) -> []PeerLocation`**
- **`PublishRoot(ctx, ownerID, rootPointer) -> version`**
- **`ResolveRoot(ctx, ownerID) -> rootPointer`**
- **`SendWrappedKey(ctx, ownerID, recipientID, wrappedKeyEnvelope) -> ack`**
- **`SendRevocation(ctx, ownerID, recipientID, revocationNotice) -> ack`**

### 19.2 Interface Invariants

- **ID invariants:**
  - `ownerID` and `peerID` shall be canonicalized before persistence or comparison.
  - `shardID` shall be deterministic from ciphertext bytes and stable across adapters.
  - CID/multihash representation shall be normalized at adapter boundaries.
- **Canonical error invariants:**
  - Core-visible errors shall be restricted to a fixed set (for example: `ErrNotFound`, `ErrUnauthorized`, `ErrUnavailable`, `ErrConflict`, `ErrInvalid`, `ErrCorrupt`, `ErrTimeout`, `ErrInternal`).
  - Adapter-native errors shall be mapped to canonical errors with retained cause chains internally.
- **Consistency invariants:**
  - Root pointer version shall be monotonic and never move backwards.
  - Read-after-successful-write consistency shall hold for the writing client under normal network conditions.
  - Revocation state changes shall be durable in ledger before asynchronous network fan-out.
- **Security invariants:**
  - Plaintext shall never traverse network ports.
  - Wrapped keys and revocation notices shall be authenticated and integrity-protected.
  - Adapter logs/metrics shall not expose secret material.

---

## 20. Package & Dependency Direction

- **Core packages remain adapter-agnostic:** `internal/crypto`, `internal/shard`, `internal/store`, `internal/ledger`, and domain orchestration shall avoid direct dependency on Kubo-specific code.
- **Adapter packaging (as implemented):**
  - `internal/ipfs/port.go` for Core-facing port interfaces (`BlockStore`,
    `NameService`, `PeerInfo`, deferred `Messaging`, composed `Backend`) and
    canonical error mapping to `model.ErrNetworkFailure`.
  - `internal/ipfs/kubo/` for the V1 Kubo-backed adapter (external Kubo RPC via
    `go-ipfs-api`). This is the ONLY package permitted to import Kubo,
    `go-cid`, or libp2p.
  - `internal/network/` for the V2 direct libp2p/IPFS-compatible path, gated
    behind `//go:build v2direct` and excluded from the default build/test.
  - A shared adapter conformance suite is deferred until the V2 path is
    reactivated.
- **Dependency policy:**
  - V1 may depend on Kubo APIs through the Kubo adapter only.
  - V2 direct adapter shall depend only on libp2p/IPFS libraries necessary for compliance and shall avoid introducing non-essential dependencies.
  - New third-party dependencies shall be justified through an architecture decision record before adoption.

---

## 21. Key Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Adapter behavioral drift (Kubo vs direct) | Inconsistent retrieval/share/revoke outcomes | Mandatory contract tests and parity test corpus; block milestone exit on divergence. |
| Data format divergence during migration | Cross-version incompatibility and failed restores | Checkpoint B schema freeze; compatibility tests on every release candidate. |
| Premature default switch to direct adapter | Reliability regressions in production | M7 interoperability and SLO gate before M8 switch; one-step config rollback to Kubo. |
| Scope creep from advanced collaboration features | Delayed V1/V2 delivery | Capability tier gating: advanced ACL/CRDT/CDC/vector clocks explicitly post-V2. |
| Security leakage via adapter logs/errors | Exposure of sensitive data or metadata | Canonical error mapping, redaction policy, and security log review in release checklist. |

---

## 22. Capability Tiers and Scope Gating

- **Tier C1 (V1 required):** Core encrypted storage, shard redundancy, base share/revoke, Kubo-backed IPFS interoperability.
- **Tier C2 (V2 required):** Direct adapter parity and default migration with dual-stack compatibility.
- **Tier C3 (Post-V2 optional):** Fine-grained ACL roles, CRDT collaborative conflict models, CDC optimization, and vector-clock rich synchronization.

Features in Tier C3 shall not block V1 or V2 exits unless explicitly promoted by a future release decision.
