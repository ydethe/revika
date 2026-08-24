# CLI Package

The `cli` package provides an interactive REPL shell for interacting with the Revika User Daemon over IPC.

## Types

- **Shell**: Interactive CLI shell connected to a daemon via Unix socket.

## Key Methods

- `NewShell(ipcAddr)` — Create a new CLI shell.
- `Run()` — Start the interactive REPL loop.
- `Close()` — Close the IPC connection.
- Command methods: `Connect()`, `Cd()`, `Pwd()`, `Ls()`, `Cp()`, `Rm()`, `Share()`, `Revoke()`.

## Interactive Commands

The shell supports the following commands:

- `connect <network_type>` — Join the network (Public, Hybrid, Private)
- `cd <path>` — Change working directory
- `pwd` — Print current working directory
- `ls [path]` — List files at path
- `cp <src> <dst>` — Copy a file
- `rm <path>` — Remove a file
- `share <file> <peer_id>` — Share a file with another peer
- `revoke <file> <peer_id>` — Revoke access to a file
- `help` — Show help message
- `exit` — Exit the CLI

## IPC Communication

Commands are sent to the daemon as JSON-RPC 2.0 requests over a Unix socket. The daemon responds with JSON-RPC 2.0 responses.

The shell opens a **single persistent connection per session** and caches it
together with its JSON encoder/decoder (reusing one decoder so buffered bytes
are never lost between requests). The daemon serves multiple sequential requests
over this connection.

The connection is **self-healing** on write: if sending a request fails (for
example, the daemon closed a stale connection), the shell dials a fresh
connection once and retries the write. A failed **read** is never retried —
the request may already have executed on the daemon, and commands such as
`cp`/`rm`/`share`/`revoke` are not idempotent.

Example request:
```json
{
  "method": "ls",
  "params": {"path": "/"},
  "id": 1
}
```

Example response:
```json
{
  "result": {"path": "/", "files": []},
  "id": 1
}
```

## Error Handling

Errors are reported as JSON-RPC 2.0 error responses with error codes:
- `-32601`: Method not found
- `-32602`: Invalid params
- `-1`: Internal error
