# `internal/store` Package

**Purpose**: Persistent storage backend for encrypted shards on Nodes. Implements file-based shard storage with atomic index updates and thread-safe concurrent access.

## Overview

The `store` package provides a pluggable storage backend for encrypted shards. Phase 1 implements a file-based backend (`LocalFileStore`) that stores shards as `.bin` files and maintains a JSON index for efficient lookup.

## Design Decisions

### 1. File-Based Storage (Phase 1)

```
.revika/node-store/
├── shard-index.json          # JSON index of all shards
├── {shard_id_1}.bin          # Shard 1 (encrypted)
├── {shard_id_2}.bin          # Shard 2 (encrypted)
├── {shard_id_3}.bin          # Shard 3 (encrypted)
└── ...
```

- **Why File-Based**: Simple, portable, works without database
- **Why .revika/**: Matches project's reserved runtime state directory
- **Index Format**: JSON for human readability and portability
- **Atomic Updates**: Uses temp file + rename for crash-safety

### 2. FileBackend Interface

```go
type FileBackend interface {
    PutShard(id string, data []byte) error
    GetShard(id string) ([]byte, error)
    DeleteShard(id string) error
    ListShards() ([]string, error)
    HasShard(id string) (bool, error)
}
```

- **Pluggable**: Future phases can implement RocksDB, S3, etc.
- **Minimal API**: Only essential operations
- **Error Semantics**: Clear error messages for not-found, permission, I/O errors

### 3. Thread-Safe Concurrent Access

```
LocalFileStore uses:
- sync.RWMutex for index protection
- Read operations use RLock (multiple concurrent readers)
- Write operations use Lock (exclusive access)
- Goroutine-safe for concurrent uploads/downloads
```

### 4. Index Persistence

**Index Format** (`.revika/node-store/shard-index.json`):

```json
{
  "shards": {
    "a1b2c3d4ef...": {
      "path": ".revika/node-store/a1b2c3d4ef....bin",
      "size": 1048576,
      "created": "2026-08-22T12:00:00Z"
    },
    "f5e4d3c2b1...": {
      "path": ".revika/node-store/f5e4d3c2b1....bin",
      "size": 2097152,
      "created": "2026-08-22T12:05:00Z"
    }
  }
}
```

**Why JSON Index**:
- Human-readable
- Recoverable if shard file is lost (can reconstruct from index)
- Efficient lookup: O(1) on hash map
- Atomic writes via temp file + rename

## Workflow

### 1. Initialize Store

```go
store, err := store.NewLocalFileStore(".revika/node-store/")
if err != nil {
    log.Fatal(err)
}
// Automatically creates directory and loads existing index
```

### 2. Store Shards (Upload from User)

```go
// Each shard is encrypted before being stored
for _, shard := range shards {
    err := store.PutShard(shard.ID, shard.Bytes)
    if err != nil {
        log.Printf("failed to store shard %s: %v", shard.ID, err)
    }
}
// Index is automatically updated and persisted to disk
```

### 3. Retrieve Shards (Download to User)

```go
// Retrieve any 3 shards for reconstruction
var retrievedShards []model.ShardInfo
for _, shardID := range []string{id1, id2, id3} {
    data, err := store.GetShard(shardID)
    if err != nil {
        log.Printf("failed to retrieve shard %s: %v", shardID, err)
        continue
    }
    retrievedShards = append(retrievedShards, model.ShardInfo{
        ID:    shardID,
        Bytes: data,
        Index: ..., // reconstructor needs to map this
    })
}
```

### 4. Query Store

```go
// List all shards stored on this node
shards, err := store.ListShards()
if err != nil {
    log.Fatal(err)
}
log.Printf("Node stores %d shards", len(shards))

// Check if specific shard exists
exists, err := store.HasShard(shardID)
if err != nil {
    log.Fatal(err)
}

// Get metadata without loading full shard data
meta, err := store.GetShardMetadata(shardID)
if err != nil {
    log.Fatal(err)
}
log.Printf("Shard %s: %d bytes, created %s", shardID, meta.Size, meta.CreatedAt)

// Get store statistics
stats := store.GetStats()
log.Printf("Total shards: %d, Total size: %d bytes", stats.TotalShards, stats.TotalSize)
```

### 5. Delete Shards (Cleanup/Revocation)

```go
// Delete specific shard
err := store.DeleteShard(shardID)
if err != nil {
    log.Printf("failed to delete shard: %v", err)
}
// Index is automatically updated
```

## Exported Types & Functions

| Type | Purpose |
|------|---------|
| `FileBackend` | Interface for pluggable storage backends |
| `LocalFileStore` | File-based implementation of FileBackend |
| `ShardIndexEntry` | Metadata entry for a single shard |
| `ShardIndex` | Complete shard index |
| `StoreStats` | Statistics about the store |

| Function | Purpose |
|----------|---------|
| `NewLocalFileStore(baseDir)` | Create file-based store, loads existing index |
| `PutShard(id, data)` | Store encrypted shard |
| `GetShard(id)` | Retrieve shard data |
| `DeleteShard(id)` | Delete shard |
| `ListShards()` | List all shard IDs |
| `HasShard(id)` | Check if shard exists |
| `GetShardMetadata(id)` | Get metadata without loading data |
| `GetStats()` | Get store statistics |

## Error Handling

| Error | Cause | Example |
|-------|-------|---------|
| `"shard X not found"` | GetShard called on non-existent shard | Network error; shard lost |
| `"failed to write shard file: ..."` | Disk full, permission denied | I/O error during upload |
| `"shard written but index save failed"` | Shard written but index update failed | Rare; recoverable but logged |
| `"failed to delete shard file: ..."` | Shard file already deleted | Cleanup after crash |

## Thread Safety Guarantees

- **Concurrent Reads**: Multiple goroutines can call `GetShard()` simultaneously
- **Concurrent Writes**: `PutShard()` and `DeleteShard()` are serialized via mutex
- **Index Consistency**: Index is locked during update; no partial updates visible to readers
- **Atomic Index Persistence**: Temp file + rename prevents corruption on crash

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `PutShard` | O(n) | n = shard size (file I/O) + JSON index update |
| `GetShard` | O(n) | n = shard size (file I/O) |
| `DeleteShard` | O(n) | n = shard size (file deletion) |
| `ListShards` | O(1) | In-memory hash map iteration |
| `HasShard` | O(1) | Hash map lookup |
| `GetShardMetadata` | O(1) | Hash map lookup (no I/O) |
| `GetStats` | O(k) | k = number of shards (summation) |

## Storage Backend Abstraction

The `FileBackend` interface allows future implementations:

### RocksDB (Phase 2)
- Key-value store for shards
- Efficient range queries for shard deletion
- Built-in compression for storage savings

### S3 Compatible (Phase 2+)
- Store shards on S3, Minio, or compatible service
- Enables cloud node participation
- Automatic redundancy at provider level

### Tiered Storage (Phase 3+)
- Hot tier: Recent shards in SSD for fast retrieval
- Cold tier: Old shards archived to slower storage
- Automatic migration based on age

## Security Properties

1. **No Decryption**: Node never decrypts shards; cannot access plaintext even if compromised
2. **Tamper Detection**: Shard ID = SHA256(encrypted_shard_bytes); changes are detected
3. **Shard-ID Validation at the Boundary**: `PutShard`/`GetShard`/`DeleteShard`/`HasShard` reject any ID that does not match `^[0-9a-f]{64}$` (hex SHA256) before touching the filesystem, guarding against path traversal and invalid filenames
4. **Access Control**: Phase 2+ will add authentication (only authorized users retrieve shards)
5. **No Metadata Leaks**: Index doesn't reveal file content (only shard IDs and sizes)

## Deferred to Future Phases

- **Distributed Index**: Phase 2 gossip protocol will sync shard locations across nodes
- **Shard Replication**: Phase 2 will implement replication strategy (which nodes store which shards)
- **Garbage Collection**: Phase 3 retention policies (automatically delete old versions)
- **Compression**: Phase 2+ may compress shards (transparent to callers)
- **Encryption at Rest**: Phase 3 may add node-level encryption (different from shard encryption)

## Testing

Run tests:
```bash
go test ./internal/store/ -v
```

Test coverage includes:
- Directory creation and index loading
- Put/get/delete shard operations
- Index persistence across instances
- Concurrent operations (10+ goroutines)
- Error cases: missing directory, disk full simulation, corrupted index
- Metadata queries and statistics
