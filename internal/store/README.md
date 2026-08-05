# store

Package `store` defines revika's content-addressed shard store — the storage
seam that every higher layer (encryption, erasure coding, repair, networking)
targets. A shard's identifier *is* the SHA-256 of its bytes, which makes the
store self-verifying (tampered or truncated data fails its ID check) and
idempotent (storing identical bytes twice yields the same ID).

The `Store` interface deliberately knows nothing about encryption, erasure
coding, or the network. This lets the encode/repair stack be built and tested
against the in-memory or on-disk backends here, then run unchanged against a
future libp2p-backed implementation.

## Fit within revika

Nodes are dumb, untrusted blob stores: they only ever hold ciphertext,
erasure-coded shards addressed by content hash. This package is that blob store.
All confidentiality lives on the User side; a node backed by a `Store` is
trusted only for availability. Content addressing is also what makes
deterministic repair work — regenerated shards reproduce their original IDs.

## Content addressing

- `ShardID` — a `[sha256.Size]byte` array; the content address of a shard.
- `HashOf(data []byte) ShardID` — returns the `ShardID` addressing `data`.
- `ShardID.String() string` — renders the ID as lowercase hex.

## Errors

- `ErrNotFound` — returned by `Get`/`Delete` when a shard is absent.
- `ErrCorrupt` — returned by `Get` when stored bytes no longer hash to their ID.

## Interfaces

### `Store`

Content-addressed blob store; implementations must be safe for concurrent use.

- `Put(ctx, data) (ShardID, error)` — stores `data`, returns its content
  address; putting identical bytes again is a no-op returning the same ID.
- `Get(ctx, id) ([]byte, error)` — returns the bytes for `id`, or `ErrNotFound`;
  verifies the bytes hash to `id`, returning `ErrCorrupt` otherwise.
- `Has(ctx, id) (bool, error)` — reports whether `id` is present.
- `Delete(ctx, id) error` — removes `id`, or returns `ErrNotFound`.

### `Lister`

Optional capability a `Store` may implement (callers type-assert for it) to
enumerate all held shard IDs. Kept off the core interface because not every
backend can cheaply enumerate. A Node uses it to (re)announce DHT provider
records on startup and on a periodic reprovide cadence.

- `List(ctx) ([]ShardID, error)` — returns the IDs of every shard held.

## Disk capacity (`diskusage.go`)

`DiskUsage(path) (Usage, error)` reports the `Total`/`Avail` bytes of the
filesystem backing a directory — the capacity signal the rebalancer needs to
equalize how *full* nodes are rather than how many shards they hold
([Architecture §3.4](../../Architecture.md)). It is a per-OS split:
`syscall.Statfs` on Linux (`diskusage_linux.go`), a portable stub returning
`ErrUnsupported` elsewhere (`diskusage_other.go`), mirroring the split in
[`internal/fsmeta`](../fsmeta/). A node folds this with its ledger byte total and
the operator `-capacity` budget into the `LoadReport` it advertises.

## Backends

### `MemStore` (`mem.go`)

In-memory store, primarily for tests and the development "mock store". Safe for
concurrent use via an `RWMutex`. Copies data on both `Put` and `Get` so callers
cannot mutate stored bytes. Implements `Store` and `Lister`.

- `NewMemStore() *MemStore` — returns an empty in-memory store.

### `DiskStore` (`disk.go`)

Persists shards as files under a root directory, fanned out by the first byte of
the ID (`…/root/ab/abcdef…`). Safe for concurrent use: writes go to a temp file
that is atomically renamed into place, and content addressing makes concurrent
writers of identical bytes harmless. Implements `Store` and `Lister`. `List`
skips entries that are not valid shard filenames (temp files, stray
directories), so a partially-written store still enumerates cleanly.

- `NewDiskStore(dir string) (*DiskStore, error)` — opens (creating if needed) a
  disk-backed store rooted at `dir`.
