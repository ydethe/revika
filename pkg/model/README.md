# `pkg/model` Package

**Purpose**: Shared type definitions and helpers used across all Revika packages.

## Overview

The `model` package defines the core data structures that represent files, shards, and ledger entries. These types are shared across `crypto/`, `shard/`, and `store/` packages to ensure type safety and clear contracts.

## Types

### ShardInfo

```go
type ShardInfo struct {
    ID    string // SHA256(encrypted_shard_bytes), hex-encoded
    Bytes []byte // encrypted shard data
    Index int    // position in k+m erasure coding scheme (0 to k+m-1)
}
```

**Purpose**: Represents an individual encrypted shard produced by the shard splitter or retrieved from storage.

**Fields**:
- **ID**: Shard identifier = SHA256(Bytes), hex-encoded. Used as key in store and for content-addressed retrieval.
- **Bytes**: Encrypted shard data. Computed by Reed-Solomon encoder from encrypted file.
- **Index**: Position in the k+m shard array. Needed by Reed-Solomon decoder to reconstruct (e.g., 0-4 for k=3, m=2).

**Reconstruction metadata is file-level, not per-shard.** `k`, `m`, and the original file size are *not* stored on `ShardInfo` — they live in `FileInfo`/the ledger. Putting them on each shard would lose them on a store round-trip (the store persists only shard bytes), so `ReconstructFile` takes them as explicit parameters sourced from `FileInfo`.

**Usage**: 
- Output of `ShardSplitter.SplitFile()`
- Input to `ShardReconstructor.ReconstructFile(shards, k, m, originalSize)`
- Stored via `LocalFileStore.PutShard(ID, Bytes)`

### FileInfo

```go
type FileInfo struct {
    Name            string            // original filename
    ContentHash     [sha256.Size]byte // SHA256 of original plaintext
    EncryptedHash   [sha256.Size]byte // SHA256 of encrypted content
    Size            int64             // original file size in bytes
    ShardCount      int               // k + m (total shards)
    DataShards      int               // k (data shards needed for reconstruction)
    ParityShards    int               // m (parity shards for redundancy)
    CreatedAt       int64             // Unix timestamp
    Owner           string            // device identifier (not enforced in Phase 1)
    GrantedToPublic []byte            // Ed25519 public keys of recipients
}
```

**Purpose**: Metadata about a file before/after sharding. Used by ledger to track file metadata.

**Fields**:
- **Name**: Original filename (e.g., "document.pdf")
- **ContentHash**: SHA256 of original plaintext. Used as seed for per-file key derivation.
- **EncryptedHash**: SHA256 of encrypted content. Could be used for deduplication.
- **Size**: Original file size in bytes (unencrypted, unpadded)
- **ShardCount**: Total number of shards (k + m)
- **DataShards**: Number of data shards (k) needed for reconstruction
- **ParityShards**: Number of parity shards (m) for redundancy
- **CreatedAt**: Unix timestamp when file was created/uploaded
- **Owner**: Device identifier of the device that created the file (not enforced in Phase 1)
- **GrantedToPublic**: List of Ed25519 public keys of users who have access (Phase 1 supports full access only)

**Note**: Phase 1 doesn't enforce fine-grained roles; Phase 4 will add read-only, write, admin permissions.

### LedgerEntry

```go
type LedgerEntry struct {
    ShardID   string // unique shard identifier
    FilePath  string // path where shard is stored on disk
    Size      int64  // shard size in bytes
    CreatedAt int64  // Unix timestamp of when shard was stored
}
```

**Purpose**: Tracks a shard stored on a Node. Used by Node to maintain local ledger.

**Fields**:
- **ShardID**: Shard identifier (same as ShardInfo.ID)
- **FilePath**: Local path to shard file (e.g., ".revika/node-store/sha256hash.bin")
- **Size**: Shard size in bytes (encrypted, padded)
- **CreatedAt**: Unix timestamp when shard was stored on this node

**Note**: Phase 1 uses this locally. Phase 2+ will gossip shard placement info across nodes.

## Helper Functions

### ComputeShardID

```go
func ComputeShardID(shardBytes []byte) string
```

**Purpose**: Compute SHA256 hash of shard bytes and return as hex-encoded string.

**Returns**: SHA256(shardBytes) as hex string (64 characters)

**Usage**:
```go
shardID := model.ComputeShardID(encryptedShardData)
// shardID = "a1b2c3d4ef5678..."
```

**Note**: This is the canonical way to compute shard IDs. Used by `shard.SplitFile()` and `shard.VerifyShardID()`.

## Design Decisions

### Why Separate FileInfo and ShardInfo?

- **FileInfo**: Metadata about the original file (for ledger, UI, directory listings)
- **ShardInfo**: Metadata about individual shards (for storage, reconstruction)
- **Separation**: Enables independent evolution (e.g., future versions may add compression info)

### Why Include Index in ShardInfo?

- **Reconstruction**: Reed-Solomon decoder needs to know which shard is which (index 0-4)
- **Phase 1 Simplicity**: Index is computed at split time; passed through storage and retrieval
- **Future**: Phase 2+ may omit Index if nodes maintain shard placement metadata

### Why Keep k/m/OriginalSize Out of ShardInfo?

- **Survives store round-trips**: The store persists only shard bytes; any reconstruction
  metadata carried on the shard would be lost on retrieval.
- **Single source of truth**: `k`, `m`, and the original file size are file-level facts, so
  they live in `FileInfo`/the ledger and are passed explicitly to
  `ReconstructFile(shards, k, m, originalSize)`.
- **Content-addressing stays clean**: `ID = SHA256(Bytes)` depends only on shard content,
  not on erasure-coding parameters.

### Why Use SHA256 for Shard IDs?

- **Content-Addressed**: Same encrypted content → same ID (enables deduplication)
- **Tamper Detection**: Modified shard → different ID (no decryption needed to verify)
- **IPFS-Compatible**: Matches IPFS content addressing model
- **Sufficient Size**: 256 bits >> 128 bits needed for 2^64 shards

## Phase 1 vs. Future Phases

| Aspect | Phase 1 | Future |
|--------|---------|--------|
| **FileInfo** | Static (created once) | May include version history |
| **GrantedToPublic** | Full access only | Fine-grained roles (read, write, admin) |
| **LedgerEntry** | Local Node storage | Gossiped across Node network |
| **Shard ID** | SHA256 | May include timestamp, device ID for dedup |

## Exported Types

| Type | Package Use |
|------|-------------|
| `ShardInfo` | shard/ (SplitFile output), store/ (PutShard input), integration_test.go |
| `FileInfo` | future ledger/ package |
| `LedgerEntry` | future node/ package |

## Exported Functions

| Function | Purpose |
|----------|---------|
| `ComputeShardID(shardBytes)` | Compute SHA256-based shard ID |

## Testing

No standalone unit tests (model is data definitions only). Model types are tested implicitly by:
- shard_test.go (ShardInfo construction and usage)
- store_test.go (ShardInfo and LedgerEntry storage)
- integration_test.go (Full workflow with model types)

## Roadmap

- **Phase 2**: Add `ShardPlacementInfo` (tracks which nodes store which shards)
- **Phase 3**: Add `UserKey` type for master key metadata (storage location, last rotation)
- **Phase 4**: Add `AccessGrant` type for fine-grained sharing (permissions, expiration)
