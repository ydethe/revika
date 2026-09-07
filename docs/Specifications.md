# Fonctionnalités

- **Principle Of Least Knowledge (PLK)** :
    - PLK001 : The Nodes shall be totally interchangeable
    - PLK002 : No Node has a special role. A bootstrap/seed node is allowed as an entry point for DHT join as it is inherent to Kademlia. But it shall not have a data/role privilege
    - PLK003 : All data stored on a Node is encrypted
    - PLK004 : All encryption routines shall be PQC compatible. Signatures are allowed to be Ed25519
- **Typology of items (ITM)** :
    - ITM001 : A Client stores in revika files. To be stored in revika, a Client splits its file in chunks. The chunks are encrypted into shards. Then the shards are stored in multiple Nodes in a RAID6 fashion so that the absence of a Node or a corrupted shard does not prevent from reconstructing the data.
- **Sharing (SHR)** :
    - SHR001 : One Client A can share access to one file to another Client B.
    - SHR002 : Roles are given to Client B on file F : a combination of Read, Write, Delete permissions can be granted
    - SHR003 : In case of Write permission, Client B can edit the file F with a conflict management
    - SHR004 : Content-Defined Chunking (CDC) shall be implemented
    - SHR005 : Conflict-free Replicated Data Type (CRDT) shall be implemented
    - SHR006 : Modifications shall be traced with Vector Clocks
- **Node discovery (DCV)** :
    - DCV001 : Their shall be a seamless mechanism to let Nodes and Clients handle a Node's deconnection or reconnection, or a new Node joining revika

# Compliance status

| ID | Requirement | Status | Evidence |
|----|-------------|:------:|----------|
| PLK001 | Nodes totally interchangeable | ✅ | Any node stores any content-addressed shard; round-robin placement (`net.PlacementStore`); no per-node data specialization. |
| PLK002 | No Node has a special role | ✅ | All nodes run the same `revika-node` binary with identical protocols. The bootstrap/seed node (`SEED_ADDR`) is only a well-known DHT entry point (explicitly allowed by the spec) and carries no data/role privilege. |
| PLK003 | All data on a Node is encrypted | ✅ | Client-side AES-256-GCM before shards leave the machine (`internal/crypto`, `pipeline.StoreFile`); nodes only ever hold ciphertext shards. |
| PLK004 | All encryption routines PQC-compatible | ✅ | Confidentiality is PQC: AES-256-GCM + ML-KEM-768 (FIPS 203) for cap wrapping. Signatures use Ed25519 (`cap/signing.go`, auth tokens, repair grants), which the spec explicitly permits. |
| ITM001 | File → chunks → encrypted shards → multi-node RAID6 | ✅ | chunk → encrypt → Reed–Solomon `k=4/m=2` (2 parity = RAID6-class) → spread across discovered nodes. Node loss tolerated by erasure decode; corruption caught by content-address hash. |
| SHR001 | Client A shares a file to Client B | ✅ (read only) | `revika-ctl share` wraps the manifest/read-cap to B's ML-KEM public key (`cmdShare`). |
| SHR002 | Grant combination of Read/Write/Delete | ❌ | Only read-cap sharing exists. No write/delete capability granting; the write-cap→read-cap→verify-cap chain is unimplemented. |
| SHR003 | Write permission + conflict management | ❌ | Not implemented. |
| SHR004 | Content-Defined Chunking | ❌ | Fixed-size chunking only (`chunk.Fixed`, 4 MiB). CDC documented as planned. |
| SHR005 | CRDT | ❌ | No CRDT code in the tree. |
| SHR006 | Modifications traced with Vector Clocks | ❌ | No vector-clock code in the tree. |
| DCV001 | Seamless node disconnect / reconnect / join | ✅ (largely) | Kademlia DHT discovery, provider records + 12h reprovide, `Reconcile` on startup, autonomous repair loop regenerates shards after node loss; clients survive a node vanishing mid-fetch via "any k of k+m." |

