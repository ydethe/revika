# Daemon Package

The `daemon` package implements the User Daemon service — a background service that manages user-side file operations, IPC communication, and network connectivity.

## Types

- **Service**: Manages the IPC server, the IPFS backend, and the ledger for the user daemon.

## Key Methods

- `NewService(ledgerPath, apiAddr, ipcAddr)` — Create a new user daemon backed by a Kubo IPFS adapter. `apiAddr` is the Kubo RPC API address (default `127.0.0.1:5001`). Adapter construction is lazy, so a service can be created without a running Kubo daemon.
- `Start()` — Start listening for IPC connections.
- `Stop()` — Gracefully shut down the daemon.
- `HandleIPCRequest(req)` — Process a JSON-RPC 2.0 IPC request.
- `GetPeerID()` — Get the IPFS peer ID of this daemon (via the Kubo adapter).

## IPC Connection Lifecycle

The IPC server serves **multiple sequential requests over a single persistent
Unix-socket connection**. `handleIPCConnection` loops decode → handle → encode
until the client disconnects (a clean `io.EOF` is not treated as an error). This
is the intended design: the CLI dials once per session and reuses the
connection, so there is **no** one-request-per-connection close.

Live connections are tracked in a `map[net.Conn]struct{}` guarded by a mutex,
and in-flight handlers are counted with a `sync.WaitGroup`. On `Stop()` the
service stops accepting new connections, force-closes every live connection so
handlers parked on `Decode` unblock instead of leaking, and waits for all
handler goroutines to exit before saving the ledger and removing the socket.

## IPC Commands

The daemon exposes the following commands via JSON-RPC 2.0 over Unix socket:

- `connect` — Join the network.
- `ls` — List files at a path.
- `cd` — Change working directory.
- `pwd` — Print working directory.
- `cp` — Copy a file.
- `rm` — Remove a file.
- `share` — Share a file with another peer.
- `revoke` — Revoke access to a file.

## Architecture

The daemon orchestrates:
1. **IPFS backend** (`internal/ipfs` port, satisfied by the `internal/ipfs/kubo` adapter): content-addressed connectivity over an **external Kubo daemon**. The daemon depends on the `ipfs.Backend` port, NOT on `*network.Host`.
2. **Ledger** (`internal/ledger`): Metadata tracking for the user's files.
3. **IPC Server**: Unix socket listener for CLI commands.

> **Operational requirement:** V1 requires a running Kubo daemon (`ipfs daemon`) alongside revika.

## Lifecycle

```go
svc, _ := NewService(ledgerPath, "127.0.0.1:5001", "/tmp/daemon.sock")
svc.Start()  // Accept IPC connections
defer svc.Stop() // Graceful shutdown: force-close live connections, wait for
                 // handlers, save ledger
```

## Error Handling

IPC errors follow JSON-RPC 2.0 error codes:
- `-32601`: Method not found
- `-32602`: Invalid params
- `-1`: Internal error
