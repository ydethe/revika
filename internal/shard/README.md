# `internal/shard` Package

**Purpose**: Reed-Solomon erasure coding for file splitting and reconstruction. Files are split into data and parity shards such that loss of some shards does not result in data loss.

## Overview

The `shard` package implements Reed-Solomon erasure coding using the battle-tested `klauspost/reedsolomon` library. It enables Revika to distribute files across multiple nodes with configurable redundancy.

## Design Decisions

### 1. Erasure Coding Parameters

- **Default**: k=3 (data shards), m=2 (parity shards)
- **Maximum**: k+m ≤ 256 shards (Reed-Solomon limitation)
- **Interpretation**: Any 3 of the 5 shards can reconstruct the original file
- **Why k=3, m=2**:
  - Tolerates loss of up to 2 nodes (40% fault tolerance)
  - Overhead: 66% storage increase (3 original → 5 total)
  - Balance between redundancy and storage cost
  - Can be adjusted per deployment

### 2. Shard ID = SHA256(encrypted_shard_bytes)

```
Shard ID = SHA256(shard_bytes), hex-encoded
```

- **Content-Addressed**: Shard ID is derived from its content, not assigned
- **Deterministic**: Same shard bytes → same ID
- **Integrity Verification**: No decryption needed to verify shard hasn't been tampered
- **IPFS-Compliant**: Uses content addressing like IPFS/IPNS
- **Collision Resistance**: SHA256 provides 2^256 collision resistance

### 3. Shard Structure

Each shard includes:
- **ID** (SHA256 hash, hex): `"a1b2c3d4..."`
- **Bytes**: Encrypted shard data (Reed-Solomon encoded)
- **Index**: Position in k+m scheme (0 to k+m-1), used for reconstruction

`ShardInfo` deliberately does **not** carry `K`, `M`, or the original file size.
Those are file-level reconstruction parameters that live in `FileInfo`/the ledger
(the store only persists shard bytes, so per-shard copies would be lost on a
round-trip). The caller passes them to `ReconstructFile(shards, k, m, originalSize)`.

### 4. Shard Reconstruction

The reconstructor knows k (number of data shards needed) and receives any k or more shards. It:
1. Places shards by their index in the k+m array
2. Fills missing positions with nil (Reed-Solomon marks as erased)
3. Reconstructs missing shards via XOR operations
4. Returns concatenated shard data

## Workflow

### Step 1: Split Encrypted File into Shards

```
Input: encrypted_file_bytes (already encrypted by crypto package)
↓
SplitFile(encrypted_file_bytes)
↓
Output: []ShardInfo{
	{ID: "sha256...", Bytes: shard_0, Index: 0},
	{ID: "sha256...", Bytes: shard_1, Index: 1},
	{ID: "sha256...", Bytes: shard_2, Index: 2},
	{ID: "sha256...", Bytes: shard_3, Index: 3},
	{ID: "sha256...", Bytes: shard_4, Index: 4},
}
```

### Step 2: Distribute Shards to Nodes

- Store each shard on a different node via network protocol
- Nodes store encrypted shard bytes; cannot decrypt without user's key

### Step 3: Retrieve and Reconstruct

```
Input: Any 3 of 5 shards (+ k, m, originalSize from FileInfo/ledger)
↓
ReconstructFile(shards, k, m, originalSize)
↓
Output: reconstructed_encrypted_file_bytes (matches original)
↓
Decrypt with crypto.FileEncryption.DecryptFile()
↓
Output: plaintext
```

## Usage Examples

### Example 1: Split File into Shards

```go
package main

import (
	"github.com/revika/revika/internal/shard"
)

func splitFile(encryptedContent []byte) ([]model.ShardInfo, error) {
	// Create splitter with default parameters (k=3, m=2)
	splitter := shard.NewShardSplitterDefault()

	// Split encrypted file into 5 shards
	shards, err := splitter.SplitFile(encryptedContent)
	if err != nil {
		return nil, err
	}

	// Each shard now has:
	// - ID: SHA256(shard_bytes)
	// - Bytes: the shard data
	// - Index: position 0-4
	return shards, nil
}
```

### Example 2: Reconstruct from Any 3 Shards

```go
func reconstructFile(shards []model.ShardInfo, k, m int, originalSize int64) ([]byte, error) {
	// Stateless reconstructor; k, m, originalSize come from FileInfo/ledger
	reconstructor := shard.NewShardReconstructor()

	// Reconstruct from any k shards (order doesn't matter)
	reconstructed, err := reconstructor.ReconstructFile(shards, k, m, originalSize)
	if err != nil {
		return nil, err
	}

	return reconstructed, nil
}
```

### Example 3: Verify Shard Integrity

```go
func verifyShard(shard model.ShardInfo) bool {
	// Verify that shard ID matches SHA256(shard_bytes)
	// No decryption needed; works on ciphertext
	return shard.VerifyShardID(shard)
}

func verifySingleShard(shardBytes []byte) [32]byte {
	// Get SHA256 hash of shard (can be verified by anyone)
	return shard.VerifyShardIntegrity(shardBytes)
}
```

## Exported Types & Functions

| Type | Purpose |
|------|---------|
| `ShardSplitter` | Splits encrypted file into k+m shards |
| `ShardReconstructor` | Reconstructs original file from any k shards |

| Function | Purpose |
|----------|---------|
| `NewShardSplitter(k, m)` | Create splitter with custom parameters |
| `NewShardSplitterDefault()` | Create splitter with defaults (k=3, m=2) |
| `ShardSplitter.SplitFile(fileBytes)` | Split file into shards |
| `NewShardReconstructor()` | Create stateless reconstructor |
| `ShardReconstructor.ReconstructFile(shards, k, m, originalSize)` | Reconstruct from k or more shards |
| `VerifyShardID(shard)` | Verify shard ID matches its content hash |
| `VerifyShardIntegrity(shardBytes)` | Compute SHA256 hash of shard |

## Constants

```go
const (
    DefaultK = 3 // data shards needed for reconstruction
    DefaultM = 2 // parity shards for redundancy
)
```

## Redundancy & Fault Tolerance

| Configuration | Data Shards | Parity | Total | Fault Tolerance |
|---------------|------------|--------|-------|-----------------|
| k=3, m=2 (default) | 3 | 2 | 5 | 2 nodes (40%) |
| k=2, m=3 | 2 | 3 | 5 | 3 nodes (60%) |
| k=4, m=3 | 4 | 3 | 7 | 3 nodes (43%) |
| k=6, m=4 | 6 | 4 | 10 | 4 nodes (40%) |

## Security Properties

1. **Shard Integrity**: SHA256-based IDs enable tamper detection without decryption
2. **Confidentiality**: Shards are encrypted before erasure coding; nodes cannot decode individual shards
3. **Reconstruction Safety**: Any k shards suffice; no need to retrieve all k+m
4. **Deterministic IDs**: Same encrypted content → same shard IDs (enables deduplication by hash)

## Design Rationale: Why Reed-Solomon?

- **Mature Library**: `klauspost/reedsolomon` is audited, battle-tested in production
- **Optimal Recovery**: k shards are necessary and sufficient (RAID-5/6 equivalent)
- **Configurable**: Can adjust k, m per use case
- **Efficient**: XOR-based encoding/decoding is fast
- **No Copy-Based Replication**: More efficient than plain replication (k=1, m=k-1)

## Deferred to Future Phases

- **Shard Scheduling**: Phase 2 will implement node selection strategy (reputation, latency, etc.)
- **Adaptive Redundancy**: Phase 4 may adjust k, m based on node reliability metrics
- **Distributed Reconstruction**: Phase 2+ may implement peer-assisted reconstruction
- **Shard Validation Protocol**: Phase 2+ may add merkle trees for batch verification

## Testing

Run tests:
```bash
go test ./internal/shard/ -v
```

Test coverage includes:
- Parameter validation (k, m, size bounds)
- Roundtrip: split → reconstruct for various file sizes (100B to 1MB)
- Parity resilience: lose 0, 1, 2 shards and still reconstruct
- Index tracking and reconstruction from shuffled shards
- Edge cases: insufficient shards, mismatched shard lengths, invalid indices
- Determinism: same plaintext → same shards
- Benchmarks: 10MB file split/reconstruct performance
