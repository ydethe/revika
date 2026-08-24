# Revika Specifications

## 1. Overview

Revika is a decentralized, distributed, end-to-end encrypted storage system that enables users to store, retrieve, and share data across a peer-to-peer network without relying on a central server.

## 2. Functional Requirements

### 2.1 File Storage & Sync

- **Directory Tree Handling:** The client (both CLI and Daemon) shall support upload, download, and synchronization of complete directory trees, including nested directories and their contents. Directory trees shall be treated as atomic units for the purposes of operations and ledger tracking.
- **Local Sync:** The User Daemon shall monitor a designated local folder and automatically detect, encrypt, and upload changes to the network.
- **Lazy Loading:** Files shall be reconstructible on-demand; clients need not download entire trees locally unless explicitly requested.
- **Consistency:** The state of files and directories on the network shall remain consistent with the user's ledger and local copies (subject to network delays).

### 2.2 Encryption & Security

- **Client-Side Encryption:** All data shall be encrypted on the user's device before leaving it; servers/nodes shall never hold plaintext data.
- **Strong Key Derivation:** User credentials (password/passphrase) shall be processed through a cryptographically secure key derivation function.
- **Key Isolation:** Each user shall maintain distinct encryption keys; sharing access shall not require sharing the user's master key.

### 2.3 Redundancy & Fault Tolerance

- **Erasure Coding:** Files shall be split into data and parity shards such that loss of some shards does not result in data loss.
- **Multi-Node Storage:** Shards shall be distributed across multiple independent nodes so that no single node holds a complete file.
- **Automatic Recovery:** If nodes become unavailable, the system shall automatically replicate missing shards to maintain redundancy.

### 2.4 Ledger & State Management

- **Ledger Organization:** The ledger shall NOT be organized per-file. Instead, it shall be organized per-user and per-directory-tree to reflect the granularity of client operations and simplify state management.
- **Ledger Persistence:** The user's ledger shall be stored locally and synced to trusted peers for recovery in case of device loss.
- **Ledger Consistency:** All clients (CLI, Daemon) shall access and update the same ledger to ensure consistent state.

### 2.5 Sharing & Access Control

- **Share Mechanism:** User A shall be able to grant access to User B for specific files or directory trees by wrapping encryption keys.
- **Access Revocation:** User A shall be able to revoke User B's access to previously shared data. Upon revocation:
  - User B shall no longer be able to decrypt newly encrypted versions of shared data.
  - User B's existing decryption keys become ineffective for updated content.
  - The system shall not require deletion of data from nodes; revocation is enforced cryptographically.
  - Revocation shall be recorded in the ledger and communicated to relevant peers.
- **Share Tracking:** The ledger shall track which users have access to which directory trees/files and the status of access grants (active, revoked, pending).
- **Revocation Notification:** The system shall notify User B when their access is revoked (asynchronously, subject to network availability).

### 2.6 User CLI (Testing Interface)

- **Interactive Shell:** The CLI shall provide an interactive REPL environment for testing and manual interaction.
- **Filesystem Operations:** The CLI shall support standard filesystem commands on synced data:
  - `cd` — Change virtual working directory
  - `pwd` — Print current working directory
  - `ls` — List files/directories
  - `cp` — Copy files
  - `rm` — Remove files/directories
- **Sharing Commands:** The CLI shall support commands to share and revoke access:
  - `share <file> <recipient_id>` — Grant access
  - `revoke <file> <recipient_id>` — Revoke access
- **Network Management:** The CLI shall support commands to join and manage network connections:
  - `connect <network_type>` — Join Public, Hybrid, or Private networks
- **Daemon Communication:** The CLI shall communicate with the User Daemon via IPC to execute commands and retrieve results.

### 2.7 Network Architecture

- **Peer-to-Peer:** The system shall operate as a decentralized P2P network with no mandatory central authority.
- **Flexible Topology:** The system shall support different network topologies:
  - **Public:** Open discovery and participation (anyone can join).
  - **Hybrid:** Controlled discovery with known bootstrap nodes.
  - **Private:** Restricted to pre-configured peers only.
- **NAT Traversal:** The system shall transparently handle clients behind NAT/firewalls.
- **Peer Discovery:** The system shall support automated peer discovery on the WAN via Kademlia DHT. LAN discovery (mDNS) is deferred to a post-M2 milestone.

### 2.8 User Roles & Deployment

- **User Role:** A user stores, retrieves, and shares data; interacts via Daemon or CLI.
- **Node Role:** A server stores encrypted shards on behalf of users; can be operated as a separate service or in-process with a User Daemon.
- **Dual Role:** A single machine can act as both User and Node, contributing storage while using the system.

### 2.9 Error Handling & Availability

- **Offline Operation:** Clients shall allow local operations (file staging, metadata updates) even when offline; changes shall sync when network is restored.
- **Partial Network Failure:** The system shall continue operating if some nodes are unavailable, as long as sufficient shards remain accessible.
- **Graceful Degradation:** Operations shall fail gracefully with clear error messages rather than hanging or corrupting state.

### 2.10 Testing & Validation

- **CLI as Test Interface:** The CLI shall serve as a primary tool for functional and integration testing.
- **Mock Storage:** The system shall support a mock storage backend for testing without network participation.
- **Reproducible Scenarios:** Test scenarios (file creation, sharing, revocation, node failures) shall be repeatable via CLI commands.

## 3. Non-Functional Requirements

### 3.1 Performance

- **Upload/Download:** Large files should complete in reasonable time proportional to network bandwidth and file size.
- **Latency:** CLI commands should respond within seconds under normal network conditions.
- **Scalability:** The system should support millions of shards and hundreds of users without architectural redesign.

### 3.2 Reliability

- **Data Durability:** Stored data shall not be lost due to single or multiple node failures (within redundancy parameters).
- **Key Safety:** User keys shall be protected from disclosure; key material shall never be logged or exposed in error messages.

### 3.3 Usability

- **Clear API:** Both CLI and Daemon APIs shall be intuitive and well-documented.
- **Error Messages:** Error messages shall be actionable and guide users toward resolution.

---

## 4. Out of Scope

- **Access Control Beyond Sharing:** Fine-grained permissions (read-only, execute) are not required; sharing grants full access.
- **Version History:** Historical versions of files are not required.
- **Bandwidth Optimization:** Deduplication and delta-sync are not required (though not forbidden).
- **Regulatory Compliance:** GDPR, HIPAA, etc. compliance is not a requirement.

Scope note: the Out-of-Scope items above apply to V1 and V2 baseline releases unless explicitly promoted by a post-V2 release plan.
Clarification: baseline sharing and revocation remain in scope for V1/V2 as specified in Section 2.5 and SHR001; only advanced collaboration capabilities listed as post-V2 remain out of scope.

---

## 5. Definitions

- **Ledger:** A per-user record of what data is stored, where it is stored, and who has access. Organized per directory tree, not per individual file.
- **Shard:** An encrypted piece of a file created via erasure coding.
- **Node:** A peer that stores shards.
- **User:** A peer that stores and retrieves data.
- **Directory Tree:** A root directory and all nested subdirectories and files within it, treated as a single operational unit.
- **Access Revocation:** Cryptographic invalidation of a user's ability to decrypt shared data by re-encrypting with a new per-file key.
- **Access Grant:** A permission record in the ledger indicating that a user has been granted access to shared data.

- **Principle Of Least Knowledge (PLK)** :
    - PLK001 : The Nodes shall be totally interchangeable
    - PLK002 : No Node has a special role. A bootstrap/seed node is allowed as an entry point for DHT join as it is inherent to Kademlia. But it shall not have a data/role privilege
    - PLK003 : All data stored on a Node is encrypted
    - PLK004 : All encryption routines shall be PQC compatible. Signatures are allowed to be Ed25519
- **Sharing (SHR)** :
    - SHR001 : One Client A shall be able to share access to a file or directory tree with another Client B.
    - SHR002 : Capability-tiered sharing roles (Read/Write/Delete) are a post-V2 capability and shall not be required for V1/V2 baseline exits.
    - SHR003 : Collaborative write conflict management is a post-V2 capability and shall not be required for V1/V2 baseline exits.
    - SHR004 : Content-Defined Chunking (CDC) is a post-V2 capability and shall not be required for V1/V2 baseline exits.
    - SHR005 : Conflict-free Replicated Data Type (CRDT) support is a post-V2 capability and shall not be required for V1/V2 baseline exits.
    - SHR006 : Vector-clock-based change tracing is a post-V2 capability and shall not be required for V1/V2 baseline exits.
- **Node discovery (DCV)** :
    - DCV001 : There shall be a seamless mechanism to let Nodes and Clients handle a Node's disconnection or reconnection, or a new Node joining revika.
- **IPFS compliance (IPFS)** :
    - IPFS001 : revika shall be fully compliant with the IPFS stack. V1 shall satisfy this via a Kubo-backed adapter. V2 may switch to a direct adapter only after interoperability contract tests pass against the same compliance expectations.
    - IPFS002 : Every shard and every blob (encrypted chunk, manifest, directory) shall be addressable by a standard IPFS content identifier (CID), so any IPFS-compliant tool can locate and integrity-check it without needing to decrypt it
    - IPFS003 : revika Nodes shall be discoverable and reachable as regular IPFS/libp2p peers; peer identity, transport security, and content routing shall follow the IPFS/libp2p specifications rather than a bespoke, incompatible protocol
    - IPFS004 : revika-specific operations that have no IPFS equivalent (e.g. encrypted sharing, per-owner quotas, proof-of-possession, repair/rebalancing) may be layered on top of the IPFS stack, but shall not replace or break compliance with the standard IPFS content-addressing and exchange mechanisms
    - IPFS005 : Publication and resolution of a Client's mutable root pointer shall follow IPNS (or an IPNS-compatible mechanism), so a root can be resolved by any IPFS-compliant peer, subject to revika's encryption of its content
- **Roles (ROL)** :
    - ROL001 : A Client (User) is the principal that stores, retrieves, and shares data, and is the sole holder of the encryption keys needed to read it
    - ROL002 : A Node stores encrypted shards on behalf of one or more Clients and never gains access to plaintext data or decryption keys
    - ROL003 : A single machine may act as both a Client and a Node at the same time
    - ROL004 : revika shall be released as two artifacts: a headless Node server, and a Client daemon that syncs a local folder with the network and may optionally also run a Node in-process
- **Durability & repair (DUR)** :
    - DUR001 : The system shall detect when a shard becomes unavailable or corrupted
    - DUR002 : The system shall be able to regenerate a missing or corrupted shard from the surviving shards of the same chunk, without needing any decryption key
    - DUR003 : A regenerated shard shall keep the same content address as the shard it replaces, so no other metadata needs to change
    - DUR004 : The system shall verify, on request, that a Node genuinely holds a shard it claims to hold, without requiring the shard's bytes to be transmitted
- **Placement & rebalancing (PLC)** :
    - PLC001 : The shards of one chunk shall be distributed across distinct Nodes so that no single Node can reconstruct a chunk on its own
    - PLC002 : The system shall favour placement across Nodes with independent failure domains (different operators/networks) where possible, to reduce the risk of correlated loss
    - PLC003 : The system shall progressively rebalance stored shards across Nodes over time, so that Nodes joining, leaving, filling up, or differing in storage capacity converge towards a fair, capacity-proportional load
    - PLC004 : Rebalancing a shard from one Node to another shall never result in the shard being lost or temporarily unreachable
    - PLC005 : A Client stores in revika files. To be stored in revika, a Client splits its file in chunks. The chunks are encrypted into shards. Then the shards are stored in multiple Nodes in a RAID6 fashion so that the absence of a Node or a corrupted shard does not prevent from reconstructing the data.
- **Mutable namespace (MUT)** :
    - MUT001 : A Client's stored files and directories shall form an immutable, content-addressed tree of encrypted data
    - MUT002 : Each Client shall have exactly one mutable pointer (the root) identifying the current state of their tree; all other data is immutable
    - MUT003 : The root pointer shall carry a monotonically increasing version so that an older, stale, or rolled-back version can never be mistaken for the current one
    - MUT004 : The root pointer shall be resolvable across the network without relying on any central server
    - MUT005 : Several devices belonging to the same Client shall be able to make concurrent changes; conflicting changes shall never be silently discarded — they shall be merged or preserved as conflict copies
    - MUT006 : A Client shall be able to authorize (enroll) and de-authorize (revoke) individual devices without needing to change their overall identity; revoking a device shall prevent it from accessing data written after the revocation, but cannot retract data it already read
- **Filesystem & metadata (FSY)** :
    - FSY001 : revika shall preserve common file metadata (name, size, permissions/mode, ownership, timestamps) when storing and retrieving a file
    - FSY002 : A Client shall be able to browse their stored data as a directory hierarchy (list a directory's contents) without downloading the content of the files it contains
    - FSY003 : revika shall be able to expose stored data as a mounted filesystem, fetching a file's content on demand only when it is opened rather than eagerly downloading everything
- **Security & abuse resistance (SEC)** :
    - SEC001 : A Node shall protect itself against excessive or abusive use (connection floods, oversized requests, storage exhaustion) without needing to inspect or decrypt the content it stores
    - SEC002 : A Node shall enforce a per-Client storage quota to prevent a single Client from monopolizing its capacity
    - SEC003 : Creating a new Client identity shall have a real (non-negligible) cost, to deter an abusive actor from trivially discarding a banned identity and minting a new one
    - SEC004 : A Node shall be able to locally deny service to a Client or peer identified as abusive, independently of any central authority

---

## 6. Release Roadmap & Migration Requirements

### 6.1 Milestones (M0..M8)

- **MIG001 (M0 Port Freeze):** Revika shall define and freeze the Core<->Network port surface and canonical error taxonomy before adapter parity work begins.
- **MIG002 (M1 Core Baseline):** Revika shall pass local integration tests for encrypt/split/store/reconstruct/share/revoke workflows without requiring network transport.
- **MIG003 (M2 V1 Kubo Integration):** Revika shall provide a Kubo-backed adapter that passes adapter contract tests for shard put/get, provider discovery, and mutable root publish/resolve.
- **MIG004 (M3 Dual-Stack Introduction):** Revika shall support a dual-stack mode with single-writer and optional dual-reader behavior, with migration telemetry.
- **MIG005 (M4 V1 GA):** Revika shall release V1 with Kubo as default adapter and documented rollback/runbook procedures.
- **MIG006 (M5 Direct Adapter Parity):** Revika shall implement a direct adapter exposing the same Core port semantics and canonical error behavior as Kubo mode.
- **MIG007 (M6 Dual-Stack Hardening):** Revika shall validate mixed-cluster operation (Kubo-only, direct-only, mixed) without data format divergence.
- **MIG008 (M7 Interoperability Gate):** Revika shall pass IPFS interoperability contract tests using the direct adapter prior to any default switch.
- **MIG009 (M8 V2 GA):** Revika shall switch default adapter to direct only after M7 is complete; Kubo compatibility mode shall remain available for rollback.

### 6.2 Dual-Stack Checkpoints (A..E)

- **MIG010 (Checkpoint A - Interface Lock):** Both adapters shall implement identical Core-facing signatures and canonical errors.
- **MIG011 (Checkpoint B - Data Contract Lock):** Manifest/root pointer schemas and ID normalization rules shall be identical across adapters.
- **MIG012 (Checkpoint C - Compatibility Mode):** In dual-stack mode, writes shall go through one configured primary adapter; reads may fall back to secondary adapter.
- **MIG013 (Checkpoint D - Heterogeneous Validation):** Mixed adapter clusters shall preserve retrieval, sharing, and revocation semantics.
- **MIG014 (Checkpoint E - Safe Switch):** Switching default adapter shall require a no-migration rollback path and verified operational procedure.

### 6.3 IPFS Compliance Gating

- **MIG015:** V1 IPFS compliance shall be demonstrated via Kubo interoperability.
- **MIG016:** V2 direct adapter shall not be the default until interoperability contract tests meet or exceed V1 compliance outcomes.

---

## 7. Core-Network Interface Requirements

### 7.1 Required Port Surface

- **INT001:** The Core shall interact with networking through a bounded port interface, not adapter-specific SDK types.
- **INT002:** The interface shall include capabilities for shard put/get/exists, provider discovery, mutable root publish/resolve, wrapped-key exchange, and revocation notice delivery.
- **INT003:** Adapter-specific payloads shall be translated at adapter boundaries; Core shall consume only canonical request/response models.

### 7.2 Invariants

- **INT010 (ID Canonicalization):** Owner IDs, peer IDs, shard IDs, and CID representations shall be canonicalized before persistence/comparison.
- **INT011 (Canonical Errors):** Core-visible network/storage errors shall map to a bounded canonical set (`ErrNotFound`, `ErrUnauthorized`, `ErrUnavailable`, `ErrConflict`, `ErrInvalid`, `ErrCorrupt`, `ErrTimeout`, `ErrInternal`).
- **INT012 (Consistency):** Mutable root versioning shall be monotonic and shall not regress.
- **INT013 (Write Semantics):** Successful write acknowledgements shall imply durable ledger intent and read-after-write visibility for the writing client under normal network conditions.
- **INT014 (Security):** Plaintext shall never be transmitted over network ports; wrapped keys and revocation notices shall be integrity-protected and authenticated.
- **INT015 (Observability Safety):** Logs and metrics shall not expose key material or plaintext.

### 7.3 Hexagonal Boundary Rules

- **INT020:** Core domain packages shall not import Kubo-specific or direct-adapter-specific protocol packages.
- **INT021:** Adapters shall act as anti-corruption layers and shall map external/protocol types into canonical Core types.
- **INT022:** Contract tests shall verify equivalent Core semantics across adapters.

---

## 8. Release Scope & Capability Tiers

- **RLS001 (Tier C1 / V1 Required):** Encrypted storage, erasure coding, base share/revoke, and Kubo-backed IPFS interoperability are required for V1 exit.
- **RLS002 (Tier C2 / V2 Required):** Direct adapter parity, dual-stack compatibility checkpoints, and interoperability contract pass are required for V2 exit.
- **RLS003 (Tier C3 / Post-V2):** Fine-grained ACL, collaborative writes with CRDT semantics, CDC, and vector clocks are post-V2 capabilities and shall not block V1/V2 exits.
- **RLS004:** Out-of-Scope statements in Section 4 shall be interpreted in conjunction with tier gates; a capability becomes in-scope only when promoted by a release-tier requirement.

---

## 9. Package & Dependency Direction Requirements

- **RLS010:** Core packages shall remain adapter-agnostic and shall depend on abstractions defined at the network port boundary.
- **RLS011:** Kubo-specific dependencies shall be isolated to the Kubo adapter implementation.
- **RLS012:** Direct adapter dependencies shall be limited to libraries required for IPFS/libp2p compliance and interoperability.
- **RLS013:** New third-party dependencies shall require explicit architecture review and justification prior to adoption.

---

## 10. Risks & Mitigation Requirements

- **RLS020 (Parity Drift Risk):** Release gates shall include adapter parity contract tests to prevent semantic drift.
- **RLS021 (Schema Drift Risk):** Shared schema compatibility tests shall run at each release candidate before milestone exit.
- **RLS022 (Migration Regression Risk):** Default-adapter switch shall require rollback validation and operational runbook checks.
- **RLS023 (Scope Creep Risk):** Tier C3 features shall remain non-blocking for V1/V2 unless promoted by an explicit release decision.
