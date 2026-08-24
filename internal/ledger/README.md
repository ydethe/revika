# Ledger Package

The `ledger` package manages the persistent ledger for tracking files, shards, and access grants across trees (directory structures). It provides thread-safe operations with serialization to disk.

## Types

- **Tree**: Represents a directory tree containing files and access grants.
- **File**: Represents a file tracked in the ledger with metadata (shards, content hash, erasure-coding parameters).
- **Grant**: Represents an access grant to another peer, with optional revocation timestamp.
- **Ledger**: In-memory and persisted ledger managing multiple trees and revocations.

## Key Methods

- `Load(path)` — Load ledger from disk; returns empty ledger if file not found.
- `Save(path)` — Atomically save ledger to disk (write temp, rename).
- `AddTree(id, rootPath)` — Create a new directory tree.
- `AddFile(treeID, fileID, filePath, contentHash, shards, k, m)` — Track a file in the ledger.
- `RemoveFile(treeID, fileID)` — Remove a file from the ledger.
- `GrantAccess(treeID, userPeerID)` — Grant access to a peer.
- `RevokeAccess(treeID, userPeerID)` — Revoke access and record audit trail.
- `GetTree(treeID)` — Retrieve a tree by ID (read-locked).
- `ListTrees()` — List all tree IDs.

## Thread Safety

All operations are protected by a read-write mutex:
- Write operations (Add, Remove, Grant, Revoke) acquire exclusive lock.
- Read operations (Get, List) acquire shared lock.
- Load/Save transactions hold the lock for entire operation to ensure consistency.

## Persistence

The ledger is serialized to JSON with indentation for readability. Atomic writes use a temp-file-then-rename pattern to ensure durability.

## Error Handling

Errors use static error types from `pkg/model`:
- `ErrFileNotFound` — Tree or file does not exist.
- `ErrInvalidPath` — Invalid or duplicate tree/file ID.
- `ErrLedgerCorrupted` — Ledger file is corrupted or unreadable.
