# ledger

A Node's per-node index of *what it stores, for whom, and under what accounting*.

This is the "ledger" reserved in `.gitignore` — a **local SQLite bookkeeping
database, not a global blockchain**. There is no consensus and no shared state:
each node owns its own ledger.

## Purpose

The blob store (`internal/store`) is the source of truth for *bytes*; the ledger
is the source of truth for *ownership and accounting*. It answers three questions
a bare content-addressed blob store cannot:

- **Who owns a shard?** A shard carries a set of owner public keys (a refcount by
  owner). Because content addressing dedups identical bytes, several Users may back
  one physical blob; each is charged, and each may independently drop its claim.
  The blob is only truly deletable once no owner remains.
- **Is an owner over quota?** Each owner is charged the shard's full size on its
  first claim, so a PUT can be refused *before* more bytes are accepted.
- **What is collectible?** Shards with no remaining owner (and optionally shards
  whose leases have all expired) can be garbage-collected.

## Location & backend

- DB path: `.revika/ledger/ledger.db` (pass `":memory:"` for an ephemeral test DB).
- Backend: SQLite via the pure-Go, cgo-free `modernc.org/sqlite` driver, keeping
  revika's build cgo-free.
- Opened WAL-mode with `busy_timeout` and `foreign_keys=on`; writes are serialised
  through a single connection (`SetMaxOpenConns(1)`) so concurrent PUT/DELETE never
  hit "database is locked".

## Schema / concepts

- **`shards`** — one row per distinct content-addressed blob: `id`, `size`,
  `created`.
- **`owners`** — `(shard_id, owner)` claims with `put_at` and `expiry` (the lease).
- **`accounts`** — per-owner rollup: `bytes_used`, `shard_count` (drives quota).
- **`stripes`** — erasure context for a held shard: `k`, `m`, sibling shard IDs,
  and a signed repair `grant`. Foreign-keyed to `shards` with `ON DELETE CASCADE`,
  so a stripe row disappears when its shard row is dropped.

**Leases** are advisory: an `expiry` of 0 never expires; otherwise GC may reclaim
expired shards only when run with `expireLeases=true`.

## Exported API

Types:
- `Ledger` — the SQLite-backed index; safe for concurrent use.
- `Options` — `QuotaBytes` (0 = unlimited) and `LeaseTTL` (0 = no expiry).
- `OwnerStat`, `Stats` — per-owner and aggregate reporting snapshots.
- `StripeRow` — one shard's erasure context (K/M, siblings, grant).
- `ReconcileReport` — result of a `Reconcile` pass.
- Errors: `ErrQuotaExceeded`, `ErrUnauthorized`.

Functions / methods:
- `Open(path, opts) (*Ledger, error)` — open/create the DB and init the schema.
- `(*Ledger) Close()` — close the underlying DB.
- `(*Ledger) QuotaBytes()` — configured per-owner quota.
- `(*Ledger) AddOwner(id, owner, size, now) (added, err)` — record a claim or renew
  a lease; enforces quota. `added` is true only for a new claim (charged once).
- `(*Ledger) RemoveOwner(id, owner) (remaining, err)` — drop a claim; returns
  remaining owners, or `ErrUnauthorized` if the caller never owned it.
- `(*Ledger) DropRecord(id)` — remove a shard record (called after the blob is
  deleted), crediting affected owners.
- `(*Ledger) CollectRecord(id, now, expireLeases) (bool, err)` — atomically drop a
  record only if still collectible (races with a re-claiming PUT are honoured).
- `(*Ledger) Collectible(now, expireLeases) ([]ShardID, error)` — list shards
  eligible for GC.
- `(*Ledger) Account(owner) (bytesUsed, shardCount, err)` — an owner's usage.
- `(*Ledger) Stats() (Stats, error)` — aggregate snapshot for metrics/status.
- `(*Ledger) PutStripe(id, k, m, siblings, grant)` — record/replace stripe context.
- `(*Ledger) Stripes() ([]StripeRow, error)` — all stripe contexts (repair loop
  enumerates these).
- `(*Ledger) Reconcile(ctx, blobs) (ReconcileReport, error)` — align the ledger
  with blobs on disk at startup: drop records whose blob is gone (crediting owners),
  retain and report orphan blobs, and recompute account totals.

## How it fits into revika

Per the guiding principle, **nodes are dumb, untrusted blob stores** — but they
still meter and gate what they accept. A node's storage server consults the ledger
to admit a PUT (quota check via `AddOwner`), to authorize a DELETE (ownership check
via `RemoveOwner`), to garbage-collect abandoned/expired shards (`Collectible` +
`CollectRecord`), to drive ciphertext-only repair (`Stripes`/`PutStripe`), and to
report storage usage (`Stats`). The ledger sees only content hashes, owner public
keys, sizes, and opaque repair grants — never plaintext or decryption keys.
