# Node Package

The `node` package implements the Node server business logic — a server that stores shards and participates in the Revika distributed network.

## Types

- **Server**: Orchestrates the store, IPFS backend, and ledger components.

## Key Methods

- `NewServer(storeDir, ledgerPath, apiAddr)` — Create a new node server backed by a Kubo IPFS adapter. `apiAddr` is the Kubo RPC API address (default `127.0.0.1:5001`). Adapter construction is lazy, so a server can be created without a running Kubo daemon.
- `Start()` — Start the server.
- `Stop()` — Gracefully shut down the server (saves the ledger).
- `StoreShard(ctx, data)` — Persist a shard to the store of record AND `AddBlock` + `Provide` it on the Kubo backend; returns a `model.ShardRef{Hash, CID, Index}`.
- `GetStats()` — Get storage statistics (shard count, total size, connected peers).
- `GetPeerID()` — Get the IPFS peer ID of this node (via the Kubo adapter), or `""` if unreachable.

## Architecture

The Node server coordinates three core components:

1. **Store** (`internal/store`): Durable ciphertext shard storage — the **store of record**. Nodes hold ciphertext they cannot read.
2. **IPFS backend** (`internal/ipfs` port, satisfied by the `internal/ipfs/kubo` adapter): content-addressed distribution over an **external Kubo daemon**. The Node depends on the `ipfs.BlockStore` / `ipfs.PeerInfo` port, NOT on `*network.Host`.
3. **Ledger** (`internal/ledger`): Metadata tracking (`File.Shards` is `[]model.ShardRef`).

Shards are stored as single-block CIDv1 (`raw` codec, `sha2-256`), so a shard's CID multihash equals its sha2-256 shard ID (`model.ComputeShardID`). The pinned Kubo blockstore is a content-addressed copy of the store-of-record shard (V1 accepts ~2× disk).

> **Operational requirement:** V1 requires a running Kubo daemon (`ipfs daemon`) alongside revika.

## Lifecycle

```go
srv, _ := NewServer(storeDir, ledgerPath, "127.0.0.1:5001")
srv.Start()    // Start the server
defer srv.Stop() // Graceful shutdown, save ledger
```

## Error Handling

Errors are wrapped with context; initialization failures return early to prevent partial state. Kubo/network errors surface as `model.ErrNetworkFailure`.
