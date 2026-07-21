# Fonctionnalités

- **Principle Of Least Knowledge (PLK)** :
    - PLK001 : The Nodes shall be totally interchangeable
    - PLK002 : No Node has a special role
    - PLK003 : All data stored on a Node is encrypted
    - PLK004 : All encryption routines shall be PQC compatible
- **Typology of items (IMT)** :
    - ITM001 : A Client stores in revika files. To be stored in revika, a Client splits its file in chunks. The chunks are encrypted into shards. Then the shards are stored in multiple Nodes in a RAID6 fashion so that the absence of a Node or a corrupted shard does not prevent from reconstructing the data.
- **Sharing (SHR)** :
    - SHR001 : One Client A can share access to one file to another Client B.
    - SHR002 : Roles are given to Client B on file F : a combination of Read, Write, Delete permissions can be granted
    - SHR003 : In case of Write permission, Client B can edit the file F with a conflict management
    - SHR004 : Content-Defined Chunking (CDC) shall be implemented
    - SHR005 : Conflict-free Replicated Data Type (CRDT) shall be implemented
    - SHR006 : Modifications shall be traced with Vector Clocks
- **Node discovery (DCV)** :
    - DCV001 : Clients and Nodes shall periodically update the list of discovered Nodes
