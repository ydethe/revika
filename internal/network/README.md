# Network Package

> **Status: dormant (V2).** This direct go-libp2p implementation is gated behind
> the `//go:build v2direct` tag and is excluded from the default
> `go build ./...` / `go test ./...`. The active V1 network layer is the
> Kubo-backed adapter in [`internal/ipfs`](../ipfs/README.md). Overlay protocols
> (ledger-sync/share/revoke) and LAN mDNS discovery are deferred for V1.

The `network` package provides libp2p-based networking capabilities for Revika, including:
- Peer discovery (Kademlia DHT for public/hybrid networks)
- Stream-based protocol handlers
- Network type support (Public, Hybrid, Private)

## Architecture

- **host.go**: Manages libp2p host lifecycle, peer connections, and protocol registration.
- **protocol.go**: Defines protocol IDs and message routing.
- **handlers/**: Protocol-specific request handlers (PutShard, GetShard, LedgerSync, Share, Revoke).
- **types.go**: Internal stream handler types and registry.

## Types

- **NetworkType**: Enum for network modes (Public, Hybrid, Private).
- **Host**: Wraps libp2p.Host with protocol management.
- **MessageRouter**: Routes incoming streams to handlers.
- **StreamHandler**: Function type for handling libp2p streams.

## Protocol IDs

- `/revika/1.0/put-shard` — Store a shard on a node.
- `/revika/1.0/get-shard` — Retrieve a shard from a node.
- `/revika/1.0/ledger-sync` — Synchronize ledger state.
- `/revika/1.0/share` — Share a file with another peer.
- `/revika/1.0/revoke` — Revoke access to a file.

## Usage

```go
// Create a host
ctx := context.Background()
host, err := NewHost(ctx, NetworkPublic)
if err != nil {
    log.Fatal(err)
}
defer host.Close()

// Register protocol handlers
host.RegisterProtocol(ProtoPutShard, handlers.PutShardHandler(store))

// Connect to a peer
host.Connect(ctx, "/ip4/192.168.1.100/tcp/4001/p2p/QmXxxx...")

// Get connected peers
peers, _ := host.GetPeers()
```

## Error Handling

Network errors wrap with `model.ErrNetworkFailure` at the boundary.

## Thread Safety

- libp2p handles concurrent stream processing.
- Handlers must be thread-safe.
- Registry access is protected internally.
