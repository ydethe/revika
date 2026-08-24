# Changelog

All notable changes to Revika will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fixed CLI↔Daemon IPC `write: broken pipe` on the second REPL command, caused by a connection-lifecycle mismatch (the daemon closed the connection after one request while the CLI reused a cached connection). The daemon (`internal/daemon/service.go`) now serves **multiple sequential requests over a single persistent Unix-socket connection** (`handleIPCConnection` loops decode → handle → encode until the client disconnects on `io.EOF`), tracks live connections, and on `Stop()` force-closes them and waits on a `sync.WaitGroup` so handler goroutines don't leak. The CLI (`internal/cli/shell.go`) caches the connection and its JSON encoder/decoder and self-heals: a failed **write** retries once with a fresh dial, while a failed **read** is never retried (`cp`/`rm`/`share`/`revoke` are not idempotent). Wire format is unchanged — line-delimited JSON `model.IPCRequest`/`model.IPCResponse`; `pkg/model` was not modified.

### Changed

- Migrated the network layer to a **Kubo-backed IPFS adapter (V1)** (spec IPFS001). The rest of the system now depends on a capability-segregated IPFS port (`internal/ipfs/port.go`: `BlockStore`, `NameService`, `PeerInfo`, deferred `Messaging`, composed `Backend`), satisfied by the `internal/ipfs/kubo` adapter which talks to an **external Kubo daemon** over its RPC HTTP API (`github.com/ipfs/go-ipfs-api`). Only `internal/ipfs/kubo` may import Kubo/go-cid/libp2p.
- `node.Server` and `daemon.Service` now depend on the IPFS port instead of `*network.Host`. `NewServer(storeDir, ledgerPath, apiAddr)` and `NewService(ledgerPath, apiAddr, ipcAddr)` take a Kubo RPC address (default `127.0.0.1:5001`). `cmd/node` and `cmd/daemon` replace the `-network` flag with `-ipfs-api`.
- `node.Server.StoreShard` now writes to the store of record AND `AddBlock` + `Provide` on the Kubo backend. `internal/store/` remains the durable store of record (ciphertext shards); the pinned Kubo blockstore is the content-addressed transport/cache copy (V1 accepts ~2× disk).
- Ledger `File.Shards` is now `[]model.ShardRef` (was `[]string`).

### Added

- `pkg/model.ShardInfo` gained a `CID` field, and a new `model.ShardRef{Hash, CID, Index}`. Shard ID stays sha2-256 hex (integrity); CID is the network address. Shards are stored as single-block CIDv1 (`raw` codec, `sha2-256`), so a shard's CID multihash equals its `model.ComputeShardID` hash — reconciling the Phase-1 "Shard ID = SHA256" decision with IPFS002 (CID addressing).
- `internal/ipfs/README.md` documenting the port, the Kubo V1 adapter, the import invariant, and the CID⇔sha256 contract.
- **Operational requirement:** V1 requires a running Kubo daemon (`ipfs daemon`) alongside revika.

### Deprecated

- The direct go-libp2p host and its five stream-protocol handlers (`internal/network/`) are now the **dormant V2 path**, gated behind the `//go:build v2direct` tag and excluded from the default `go build ./...` / `go test ./...`. Overlay protocols (ledger-sync/share/revoke) and LAN mDNS discovery are deferred for V1.

## [0.1.0] - 2026-08-22

### Fixed

- Fixed the erasure-coding split so `SplitFile` uses the `reedsolomon` library's `Split` + `Encode`: data now fills the `k` data shards and parity fills the `m` parity shards (previously data was being written into parity positions), and `ReconstructFile` uses `Join` to recombine and trim to the original size.
- Hardened decryption error handling: `DecryptFile` and `UnwrapKey` now return a static `"decryption failed"` error instead of wrapping the internal AES-GCM authentication failure, so GCM internals do not leak to callers.
- Added shard-ID validation at the store boundary: `PutShard`/`GetShard`/`DeleteShard`/`HasShard` reject IDs that do not match `^[0-9a-f]{64}$` (hex SHA256), guarding against path traversal and invalid filenames.
- Fixed store benchmarks to use `os.TempDir()` instead of passing a nil `*testing.T` to the test-only temporary-directory helper.

### Changed

- Moved reconstruction metadata (`k`, `m`, original file size) out of `ShardInfo` and up to the file level (`FileInfo`/ledger). `ShardInfo` is now content-addressed `{ID, Bytes, Index}`; carrying these on each shard would lose them on a store round-trip, since the store persists only shard bytes.
- `NewShardSplitter(k, m)` no longer takes a `shardSize` parameter, and the `DefaultShardSize` constant was removed.
- `NewShardReconstructor()` is now stateless (takes no arguments); `ReconstructFile(shards, k, m, originalSize)` takes the reconstruction parameters explicitly, sourced from `FileInfo`/the ledger.

### Added

#### Core Packages (Phase 1)

- **`internal/crypto/`**: End-to-end encryption and key management
  - `KeyDerivation.DeriveUserMasterKey()` - PBKDF2-SHA256 master key derivation (100,000 iterations)
  - `KeyDerivation.DerivePerFileKey()` - Deterministic per-file key derivation via SHA256-based KDF
  - `FileEncryption.EncryptFile()` - AES-256-GCM encryption with random nonce
  - `FileEncryption.DecryptFile()` - AES-256-GCM decryption
  - `KeyWrapping.WrapKey()` - ECIES key wrapping with X25519 ECDH for sharing
  - `KeyWrapping.UnwrapKey()` - ECIES key unwrapping for recipients

- **`internal/shard/`**: Reed-Solomon erasure coding
  - `ShardSplitter.SplitFile()` - File splitting into k data + m parity shards (default: k=3, m=2)
  - `ShardReconstructor.ReconstructFile()` - Reconstruction from any k of k+m shards
  - `VerifyShardID()` - Content integrity verification
  - `VerifyShardIntegrity()` - SHA256-based shard hash computation
  - Support for configurable erasure coding parameters (k+m ≤ 256)

- **`internal/store/`**: Persistent shard storage backend
  - `LocalFileStore` - File-based shard storage with JSON index
  - `FileBackend` interface - Pluggable storage backend contract
  - Atomic index updates via temp file + rename
  - Thread-safe concurrent access via RWMutex
  - Shard listing, metadata queries, and store statistics

- **`pkg/model/`**: Shared type definitions
  - `ShardInfo` - Encrypted shard representation with content-addressed ID
  - `FileInfo` - File metadata before sharding
  - `LedgerEntry` - Shard tracking entry
  - `ComputeShardID()` - Deterministic shard ID computation

#### Documentation

- [README.md](README.md) - Architecture overview, design decisions, workflow examples
- [docs/Architecture.md](docs/Architecture.md) - System design, networking, data model, ledger structure
- [docs/Specifications.md](docs/Specifications.md) - Functional and non-functional requirements
- [QUICKSTART.md](QUICKSTART.md) - Quick verification guide and test summary
- [PHASE1_IMPLEMENTATION.md](PHASE1_IMPLEMENTATION.md) - Detailed implementation notes

#### Testing & Build

- **47+ comprehensive test cases**
  - `internal/crypto/`: 17 test cases covering key derivation, encryption/decryption, key wrapping
  - `internal/shard/`: 13 test cases covering splitting, reconstruction, erasure resilience
  - `internal/store/`: 14 test cases covering I/O, concurrency, index persistence
  - Integration tests: 3 end-to-end workflows
- **>80% code coverage** across all packages
- Makefile with build, test, coverage, and linting targets
- `go.mod` with minimal dependencies: `klauspost/reedsolomon`, `golang.org/x/crypto`

### Known Limitations / Deferred to Future Phases

#### Phase 2 (Network)
- User Daemon implementation (file sync, local folder monitoring)
- Node Server implementation (peer participation, shard distribution)
- libp2p networking (peer discovery, NAT traversal, multiplexed communication)
- Shard distribution and replication strategy
- Ledger gossip protocol for shard placement synchronization

#### Phase 3 (User Experience)
- Master key storage and OS keychain integration
- User CLI interactive shell with filesystem operations
- Key wrapping for shared access (manual recipient public key exchange)
- Access revocation workflow
- Multi-device synchronization and key recovery

#### Phase 4+ (Advanced Features)
- Fine-grained role-based access control (read-only, write, admin)
- Public key discovery (not manual exchange)
- Automatic shard replication and recovery
- Retention policies and garbage collection
- Multi-signature ledger consensus

### Design Decisions Locked in Phase 1

- ✅ **Shard ID = SHA256(encrypted_shard_bytes)**: Content-addressed, deterministic, IPFS-compliant
- ✅ **Per-File Key Derivation**: SHA256(master_key || file_content_hash) for determinism
- ✅ **ECIES Key Wrapping**: X25519 ECDH ephemeral key exchange for sharing
- ✅ **Erasure Coding**: k=3, m=2 by default (any 3 of 5 shards reconstruct file)
- ✅ **Node Storage Only**: Phase 1 stores encrypted shards; user ledger deferred
- ✅ **Client-Side Encryption**: All data encrypted before leaving user machine

---

## [Unreleased]

(Future versions tracked here)
