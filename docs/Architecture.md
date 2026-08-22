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
- **DHT (libp2p Kademlia)** — Peer discovery on WAN; mDNS on LAN

---

## 3. Data Model

### 3.1 File & Shard Structure

- **Directory Trees:** Client operations (Daemon and CLI) work on complete directory trees as atomic units
- **File → k+m Shards** via Reed–Solomon (using `klauspost/reedsolomon`)
  - Recommended: `k=3, m=2` (any 3 of 5 shards reconstruct the file)
  - Shard size configurable; suggest 1–10 MB for typical files
- **Shards are encrypted** individually with a file-derived symmetric key before leaving the User machine
- **Ledger entry** maps Directory Tree ID → {Shard IDs, access grants}; shard ID acts as content address for IPFS-style retrieval

### 3.2 Encryption Scheme

- **Per-File Key:** `SHA256(user_master_key || file_hash)` → AES-256-GCM encryption
- **User Master Key:** Derived from user password/passphrase (PBKDF2, stored encrypted at rest)
- **Key Sharing:** Wrap per-file key with recipient's public key; recipient unwraps to gain access
- **Key Revocation:** Invalidate wrapped key by re-encrypting file with new per-file key; old wrapped key cannot decrypt
- **Node Perspective:** Nodes hold ciphertext; cannot decrypt without user key

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

- `/revika/1.0/put-shard` — User → Node: Upload encrypted shard
- `/revika/1.0/get-shard` — User/Node → Node: Retrieve shard
- `/revika/1.0/ledger-sync` — Node ↔ Node: Gossip shard placement
- `/revika/1.0/share` — User → User: Exchange wrapped keys
- `/revika/1.0/revoke` — User → User: Notify of access revocation

### 4.2 Peer Identity

- **Node Peer ID** — libp2p-generated from Ed25519 keypair; acts as node identity
- **User Peer ID** — libp2p identity for User Daemon; separate from file encryption key
- **Peer discovery:** DHT on WAN, mDNS on LAN (configurable per network type)

### 4.3 Transport

- libp2p handles encryption (TLS 1.3), multiplexing, NAT traversal
- No bespoke wire protocol

### 4.4 Network Types (IPFS Terminology)

| Type | Discovery | Bootstrap | Use Case |
|------|-----------|-----------|----------|
| **Public** | Global DHT | Public bootstrap nodes | Open, collaborative storage |
| **Hybrid** | DHT with allowlist | Trusted bootstrap peers | Semi-open with curated nodes |
| **Private** | Manual peer config | Static peer list | Closed org/family network |

---

## 5. Module Layout (Go)

```
revika/
├── go.mod                          # Module: github.com/revika/revika
├── cmd/
│   ├── daemon/                     # User Daemon binary
│   │   └── main.go
│   ├── node/                       # Node Server binary
│   │   └── main.go
│   └── cli/                        # User CLI binary (testing)
│       └── main.go
├── internal/
│   ├── crypto/                     # Encryption, key derivation
│   ├── shard/                      # Erasure coding, shard ops
│   ├── ledger/                     # Ledger read/write, sync
│   ├── network/                    # libp2p protocol handlers
│   ├── daemon/                     # User Daemon business logic
│   ├── node/                       # Node Server business logic
│   ├── cli/                        # CLI shell, subcommand handlers
│   └── store/                      # Local storage backends (file-based, mock)
├── pkg/
│   └── model/                      # Shared types (File, Shard, Ledger)
└── docs/
    └── Architecture.md             # This document
```

---

## 6. User CLI Details

### 6.1 Shell Architecture

- **Interactive REPL** — Prompts for commands (`revika> `)
- **IPC to Daemon** — CLI communicates with User Daemon via Unix socket or TCP
- **Local State** — Maintains current working directory, network config
- **Error Handling** — Graceful feedback for network failures, permission errors

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
6. Daemon uploads each shard via `/revika/1.0/put-shard` protocol
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
- **CLI disconnection:** CLI reconnects to Daemon automatically; buffered commands retry
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
| Shard size | 1–10 MB (tunable) |
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
