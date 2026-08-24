# IPFS Package

The `ipfs` package defines revika's **IPFS port**: the capability-segregated
interfaces the rest of the system uses to reach a content-addressed network.
It is the V1 network layer (spec IPFS001 — "V1 shall satisfy this via a
Kubo-backed adapter").

The port speaks only in revika terms (`[]byte` payloads and string content
hashes/CIDs) and never leaks IPFS/CID/libp2p types to its consumers.

## Port interfaces (`port.go`)

- **`BlockStore`** — content-addressed blocks: `AddBlock`, `GetBlock`, `Pin`,
  `Provide`. Consumed by the Node.
- **`NameService`** — mutable pointer (IPNS): `PublishIPNS`, `ResolveIPNS`.
  Consumed by the Daemon.
- **`PeerInfo`** — identity/connectivity: `ID`, `Peers`, `Connect`.
- **`Messaging`** — ledger-sync/share/revoke overlays. **Deferred for V1**;
  defined for forward-compatibility only, not implemented or wired.
- **`Backend`** — composes `BlockStore` + `NameService` + `PeerInfo` (the full
  V1 surface; `Messaging` excluded).

## V1 adapter (`kubo/`)

`internal/ipfs/kubo` is the V1 adapter. It implements the port by talking to an
**external Kubo daemon** over its RPC HTTP API via
`github.com/ipfs/go-ipfs-api`. Adapter construction is lazy (no daemon contact),
so consumers can be built without a running Kubo; reachability failures surface
on the first network-touching call. Kubo/network errors are wrapped as
`model.ErrNetworkFailure`.

> **Operational requirement:** V1 requires a running Kubo daemon
> (`ipfs daemon`, default RPC `127.0.0.1:5001`) alongside revika.

## Import invariant

ONLY `internal/ipfs/kubo` may import Kubo, `go-cid`, or libp2p packages.
Consumers (`internal/node`, `internal/daemon`, `internal/cli`, `pkg/model`)
MUST stay Kubo-free.

## CID ⇔ sha256 contract

`AddBlock` stores bytes as a single-block **CIDv1, `raw` codec, `sha2-256`**
multihash, so the CID's multihash digest equals our existing sha2-256 shard
hash (`model.ComputeShardID`). This reconciles the Phase-1 "Shard ID = SHA256"
decision with IPFS002 (CID addressing):

- **Shard ID** — sha2-256 hex, the durable *integrity* identifier.
- **CID** — the *network address* used to fetch the block.

Helpers `ExpectedCID(data)` and `CIDMatchesSHA256(cid, sha256Hex)` assert this
contract. See also `model.ShardRef{Hash, CID, Index}`.

## V2 (dormant)

The direct go-libp2p implementation lives in `internal/network/` behind the
`//go:build v2direct` tag and is excluded from the default build/test.
