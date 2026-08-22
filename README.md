# Revika: Decentralized End-to-End Encrypted Storage

Revika is a decentralized, distributed, end-to-end encrypted storage system — a self-hosted Dropbox/Drive that runs over a peer-to-peer network instead of a central server.

**Current Status**: Phase 1 complete ✅ — Core cryptographic, erasure coding, and storage primitives implemented.

**Documentation**:
- [docs/Architecture.md](docs/Architecture.md) — Complete system design, data flow, networking
- [docs/Specifications.md](docs/Specifications.md) — Functional and non-functional requirements
- [QUICKSTART.md](QUICKSTART.md) — Verification guide for Phase 1
- [CHANGELOG.md](CHANGELOG.md) — Release history and roadmap

## Phase 1: Core Cryptographic Primitives

Revika Phase 1 implements the foundation for end-to-end encryption:

### Package Documentation

For detailed design decisions, usage examples, and roadmaps, see each package's README:

- **[internal/crypto/README.md](internal/crypto/README.md)** — PBKDF2 key derivation, per-file key KDF, AES-256-GCM encryption, ECIES key wrapping
- **[internal/shard/README.md](internal/shard/README.md)** — Reed-Solomon erasure coding (k=3, m=2), content-addressed shard IDs, reconstruction
- **[internal/store/README.md](internal/store/README.md)** — File-based persistent storage, JSON index, thread-safe concurrent access
- **[pkg/model/README.md](pkg/model/README.md)** — Shared types (ShardInfo, FileInfo, LedgerEntry) and helpers

### Packages

#### `pkg/model`
Shared type definitions used across all packages.

- **ShardInfo**: Represents an encrypted shard with content-addressed ID
- **FileInfo**: Metadata about a file before sharding
- **LedgerEntry**: Tracking of shards stored on this node
- **ComputeShardID()**: Deterministic shard ID as SHA256(encrypted_shard_bytes)

#### `internal/crypto`
Cryptographic operations for encryption, key derivation, and key wrapping.

**Key Derivation:**
- `DeriveUserMasterKey(password)` → 256-bit master key via PBKDF2-SHA256 (100k iterations)
- `DerivePerFileKey(masterKey, fileContentHash)` → 256-bit per-file key via SHA256-based KDF

**File Encryption:**
- `EncryptFile(plaintext, perFileKey)` → AES-256-GCM ciphertext
- `DecryptFile(ciphertext, perFileKey)` → plaintext

**Key Wrapping (ECIES):**
- `WrapKey(perFileKey, recipientPublicKey)` → encrypted key with ephemeral public key
- `UnwrapKey(wrappedKey, devicePrivateKey)` → decrypted per-file key
- Uses X25519 for ECDH key exchange

#### `internal/shard`
Reed-Solomon erasure coding for file splitting and reconstruction.

**Splitting:**
- `NewShardSplitter(k, m)` → creates Reed-Solomon encoder with k data + m parity shards
- `SplitFile(fileBytes)` → encrypts and splits into k+m shards with content-addressed IDs

**Reconstruction:**
- `NewShardReconstructor()` → creates a stateless decoder
- `ReconstructFile(shards, k, m, originalSize)` → reconstruct from any k shards (k, m, originalSize from `FileInfo`/ledger)

**Default Parameters:**
- k = 3 (data shards)
- m = 2 (parity shards)  
- Any 3 of 5 shards can reconstruct the original file

#### `internal/store`
File-based storage backend for persisted shards on a Node.

**FileBackend Interface:**
```go
type FileBackend interface {
    PutShard(id string, data []byte) error
    GetShard(id string) ([]byte, error)
    DeleteShard(id string) error
    ListShards() ([]string, error)
    HasShard(id string) (bool, error)
}
```

**LocalFileStore Implementation:**
- Stores shards as `.revika/node-store/{shard_id}.bin` files
- Maintains JSON index at `.revika/node-store/shard-index.json`
- Thread-safe with RWMutex for concurrent access
- Atomic index updates via temp file + rename

**Index Format:**
```json
{
  "shards": {
    "sha256hash1": {
      "path": ".revika/node-store/sha256hash1.bin",
      "size": 1048576,
      "created": "2026-08-22T12:00:00Z"
    }
  }
}
```

## Workflow Example

```go
// 1. Derive encryption keys
kd := &crypto.KeyDerivation{}
masterKey, err := kd.DeriveUserMasterKey("user-password")
fileHash := sha256.Sum256(plaintextContent)
perFileKey, err := kd.DerivePerFileKey(masterKey, fileHash)

// 2. Encrypt file
fe := &crypto.FileEncryption{}
encrypted, err := fe.EncryptFile(plaintextContent, perFileKey)

// 3. Split into shards
splitter := shard.NewShardSplitterDefault() // k=3, m=2
shards, err := splitter.SplitFile(encrypted)

// 4. Store shards
store, err := store.NewLocalFileStore(".revika/node-store/")
for _, shardInfo := range shards {
    store.PutShard(shardInfo.ID, shardInfo.Bytes)
}

// 5. Retrieve and reconstruct
reconstructor := shard.NewShardReconstructor()
retrievedShards := []model.ShardInfo{
    {ID: "...", Bytes: shardData1, Index: 0},
    {ID: "...", Bytes: shardData2, Index: 1},
    {ID: "...", Bytes: shardData3, Index: 2},
}
// k, m, and the original file size come from FileInfo/ledger
reconstructedEncrypted, err := reconstructor.ReconstructFile(retrievedShards, 3, 2, int64(len(encrypted)))

// 6. Decrypt
decrypted, err := fe.DecryptFile(reconstructedEncrypted, perFileKey)
// decrypted == plaintextContent
```

## Key Design Decisions (Phase 1)

1. **Shard ID = SHA256(encrypted_shard_bytes)**
   - Content-addressed, deterministic
   - Enables integrity verification without decryption
   - IPFS-compliant

2. **Per-File Key Derivation**
   - SHA256(master_key || file_content_hash)
   - Deterministic: same file always produces same key
   - Different files produce different keys

3. **Key Wrapping**
   - ECIES with X25519 ephemeral keys
   - Recipient's 32-byte public key required (X25519 format)
   - Returns: ephemeral_pubkey (32) || nonce (12) || ciphertext || tag (16)

4. **Reed-Solomon Erasure Coding**
   - k=3 data shards, m=2 parity shards by default
   - Any 3 of 5 shards can reconstruct original
   - Configurable k, m up to 256 total shards

5. **Storage**
   - Node-only storage: encrypted shards + shard index
   - User ledger persistence deferred to Phase 2/3
   - Thread-safe concurrent access
   - Atomic index updates

## Testing

All packages include comprehensive table-driven tests:

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/crypto/
go test ./internal/shard/
go test ./internal/store/
go test ./pkg/model/
```

**Test Coverage:**
- `crypto/`: Key derivation determinism, encryption/decryption roundtrip, key wrapping/unwrapping, error cases
- `shard/`: Roundtrip with k shards, parity resilience, corruption handling, concurrent access
- `store/`: File I/O, index persistence, concurrent put/get/delete, error cases
- `model/`: Type definitions and helper functions

**Benchmarks:**
```bash
go test -bench=. ./internal/shard/
go test -bench=. ./internal/store/
```

## Security Considerations

1. **Master Key Storage**: Phase 1 assumes master key available in memory. Phase 3 will integrate OS keychain (daemon/).

2. **Key Wrapping**: X25519 ECDH provides forward secrecy. Recipient private key never exposed.

3. **Encryption**: AES-256-GCM with random nonce per message (non-deterministic ciphertext).

4. **Shard Integrity**: SHA256(shard_bytes) for tamper detection. Can be verified by any reader (no decryption needed).

5. **Concurrent Access**: RWMutex protects shard index. No distributed consensus yet (deferred to Phase 2 network/).

## Known Limitations & Deferred Work

### Phase 1 Scope
✅ **Complete**:
- Client-side encryption (crypto package)
- Erasure coding (shard package)
- Persistent shard storage (store package)

❌ **Deferred to Phase 2+ (Network)**:
- User Daemon (local folder sync, IPC)
- Node Server (peer participation, shard distribution)
- libp2p networking (peer discovery, NAT traversal)
- Ledger gossip protocol (shard placement synchronization)
- Multi-device sync

❌ **Deferred to Phase 3+ (UX & Ops)**:
- Master key storage (OS keychain integration)
- User CLI (interactive shell, filesystem operations)
- Key wrapping workflow (manual public key exchange → automated discovery)
- Access revocation notification system
- Multi-user sharing UI

❌ **Deferred to Phase 4+ (Advanced)**:
- Fine-grained roles (read-only, write, admin)
- Automatic shard replication and recovery
- Retention policies and garbage collection
- Public key discovery (currently manual exchange)

### Architecture Roadmap

See [docs/Architecture.md](docs/Architecture.md) Section 5 (Module Layout) for the complete intended structure:

```
revika/
├── cmd/
│   ├── daemon/     # Phase 2: User Daemon binary
│   ├── node/       # Phase 2: Node Server binary
│   └── cli/        # Phase 3: User CLI binary (testing interface)
├── internal/
│   ├── crypto/     # ✅ Phase 1
│   ├── shard/      # ✅ Phase 1
│   ├── store/      # ✅ Phase 1
│   ├── ledger/     # Phase 2: User ledger, shard tracking
│   ├── network/    # Phase 2: libp2p protocol handlers
│   ├── daemon/     # Phase 3: User Daemon business logic
│   ├── node/       # Phase 2: Node Server business logic
│   └── cli/        # Phase 3: CLI shell and commands
└── pkg/
    └── model/      # ✅ Phase 1
```

## Building & Testing

```bash
# Build all packages
go build ./...

# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run integration tests only
go test -v -run Integration ./...

# Lint
go vet ./...
```

## Dependencies

**Required**:
- `github.com/klauspost/reedsolomon` — Reed-Solomon erasure coding (v1.12.1+)
- `golang.org/x/crypto` — Standard crypto extensions (PBKDF2, X25519)

**Standard Library Only** (no other external deps):
- `crypto/aes` — AES cipher
- `crypto/cipher` — GCM mode
- `crypto/ecdh` — X25519 ECDH
- `crypto/rand` — Cryptographically secure randomness
- `crypto/sha256` — SHA256 hashing
- `encoding/json` — JSON marshaling for ledger/index
- `sync` — Mutex for thread-safe concurrent access

**No other external dependencies** — intentional for Phase 1 security review and minimal attack surface.

## Documentation Structure

- **[docs/Architecture.md](docs/Architecture.md)** — System design, data model, networking protocols, module layout
- **[docs/Specifications.md](docs/Specifications.md)** — Functional & non-functional requirements (aligned with Phase 1)
- **Package READMEs** — [crypto](internal/crypto/README.md), [shard](internal/shard/README.md), [store](internal/store/README.md), [model](pkg/model/README.md)
- **[CHANGELOG.md](CHANGELOG.md)** — Release notes and version history
- **[QUICKSTART.md](QUICKSTART.md)** — Verification guide for Phase 1
