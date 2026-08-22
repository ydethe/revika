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
- **Peer Discovery:** The system shall support automated peer discovery on both LAN (mDNS) and WAN (DHT).

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
    - SHR001 : One Client A can share access to one file to another Client B.
    - SHR002 : Roles are given to Client B on file F : a combination of Read, Write, Delete permissions can be granted
    - SHR003 : In case of Write permission, Client B can edit the file F with a conflict management
    - SHR004 : Content-Defined Chunking (CDC) shall be implemented
    - SHR005 : Conflict-free Replicated Data Type (CRDT) shall be implemented
    - SHR006 : Modifications shall be traced with Vector Clocks
- **Node discovery (DCV)** :
    - DCV001 : Their shall be a seamless mechanism to let Nodes and Clients handle a Node's deconnection or reconnection, or a new Node joining revika
- **IPFS compliance (IPFS)** :
    - IPFS001 : revika shall be fully compliant with the IPFS stack. This shall be achieved either by implementing the relevant IPFS specifications (content identifiers/CIDs, multihash, multiaddr, peer routing, content exchange) directly, or by relying on an existing, conformant IPFS implementation (e.g. kubo) or an equivalent library, so revika Nodes interoperate with the wider IPFS/libp2p ecosystem
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
