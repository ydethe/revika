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
