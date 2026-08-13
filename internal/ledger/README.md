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
  first claim, so a PUT can be refused *before* more bytes are accepted. The
  effective ceiling can be **age-graduated** (Axis B, below) so a freshly minted
  identity starts weak and earns its full quota over time.
- **What is collectible?** Shards with no remaining owner (and optionally shards
  whose leases have all expired) can be garbage-collected.

## Location & backend

- DB path: `.revika/ledger/ledger.db` (pass `":memory:"` for an ephemeral test DB).
- Backend: SQLite via the pure-Go, cgo-free `modernc.org/sqlite` driver, keeping
  revika's build cgo-free.
- Opened with `busy_timeout` and `foreign_keys=on`; writes are serialised through a
  single connection (`SetMaxOpenConns(1)`) so concurrent PUT/DELETE never hit
  "database is locked".
- Journal mode is selectable via `Options.JournalMode` (node flag `-ledger-journal`):
  `delete`/`truncate` (rollback journal — the **default**) or `wal`. WAL relies on a
  shared-memory (`-shm`) mapping that a **network filesystem cannot provide**, so a
  ledger placed on an SMB/CIFS or NFS mount — e.g. an Azure Files volume — opened in WAL
  mode fails at open with `database is locked` (SQLITE_BUSY) even for a single opener.
  Since writes are already serialised through one connection, WAL's extra read
  concurrency buys little, so `delete` is the safe default everywhere; opt into `wal`
  only for a local-disk node. The DB is also single-writer, so a node backed by a shared
  mount must run exactly one replica.

## Schema / concepts

- **`shards`** — one row per distinct content-addressed blob: `id`, `size`,
  `created`.
- **`owners`** — `(shard_id, owner)` claims with `put_at` and `expiry` (the lease).
- **`accounts`** — per-owner rollup: `bytes_used`, `shard_count` (drives quota),
  and `first_seen` (Unix seconds of the owner's first accepted claim — the age
  clock the graduated quota ramp measures from; see **Age-graduated quota** below).
- **`stripes`** — erasure context for a held shard: `k`, `m`, sibling shard IDs,
  and a signed repair `grant`. Foreign-keyed to `shards` with `ON DELETE CASCADE`,
  so a stripe row disappears when its shard row is dropped.

**Leases** are advisory: an `expiry` of 0 never expires; otherwise GC may reclaim
expired shards only when run with `expireLeases=true`.

## Age-graduated quota (Axis B)

Banning by identity only bites if a *fresh* identity is worth little, so a banned
owner cannot re-mint and immediately flood again. Axis B makes an owner's storage
**capability grow with age**: when `Options.QuotaRamp > 0`, the effective per-owner
ceiling ramps linearly from `QuotaInitialFraction * QuotaBytes` at first sight to the
full `QuotaBytes` after `QuotaRamp` has elapsed (measured from `accounts.first_seen`).
`effectiveQuota(opts, firstSeen, now)` computes it; `QuotaRamp <= 0` (or a fraction
outside `(0, 1)`) is a flat quota, unchanged from before.

The node sets `QuotaBytes` from its `-quota` flag, which is **non-zero by default**
(issue #22): 90 GiB — 90% of a nominal 100 GiB node — so a fresh node bounds a single
owner out of the box and the Axis B ramp is active by default. `-quota 0` opts back
into an unlimited (unbounded) per-owner ceiling and is logged as a warning; with an
unlimited quota there is nothing for the ramp to graduate.

Two properties keep it from locking anyone out:

- **First-shard escape.** A brand-new owner has `bytes_used == 0` and no recorded
  `first_seen`; its very first claim is always admitted (`used == 0` bypasses the
  ceiling), which *records* `first_seen = now` so age — and standing — can start
  accruing. Without this a ramp starting near zero would refuse an owner its first
  byte and it could never establish itself.
- **Age survives reconcile.** `Reconcile` recomputes `accounts` from the surviving
  `owners` rows using `MIN(put_at)` as `first_seen`, so a restart or a ledger
  reconciliation never resets an owner's age clock (which would silently restore a
  banned-and-re-minted-looking owner to full quota).

It is a **local** node policy (wired from `revika-node -quota-ramp/-quota-initial`),
**on by default** (ramp 7 days, initial fraction 5%), but it only bites when a per-owner
`-quota` is set — with unlimited quota there is nothing to graduate, so the default node
(no quota) is unaffected. It is enforced purely on metadata the ledger already holds
(owner key, bytes, a timestamp) with no extra work on the hot path — the age term is one
arithmetic expression inside the existing `AddOwner` quota check. Pre-migration ledger
rows default `first_seen = 0` (epoch), i.e. maximal age = full quota, so upgrading a node
never retroactively throttles its existing owners. Its effective configuration is reported
on the node's `/status` (`defense.quota_ramp`), `/metrics` (`revika_quota_ramp_*`), and the
`/admin` "Self · defenses" panel. See Architecture.md §5.

## Exported API

Types:
- `Ledger` — the SQLite-backed index; safe for concurrent use.
- `Options` — `QuotaBytes` (0 = unlimited), `LeaseTTL` (0 = no expiry), and the
  Axis B graduated-quota knobs `QuotaRamp` (0 = disabled: flat quota) +
  `QuotaInitialFraction` (the fraction of the full quota a brand-new owner starts
  with, e.g. `0.05`).
- `OwnerStat`, `Stats` — per-owner and aggregate reporting snapshots.
- `LedgerFilter`, `LedgerEntry`, `EntriesResult` — the filter, row, and paginated
  result for the ledger-browser query (`DefaultEntryLimit` = 100).
- `StripeRow` — one shard's erasure context (K/M, siblings, grant).
- `ReconcileReport` — result of a `Reconcile` pass.
- Errors: `ErrQuotaExceeded`, `ErrUnauthorized`.

Functions / methods:
- `Open(path, opts) (*Ledger, error)` — open/create the DB and init the schema.
- `(*Ledger) Close()` — close the underlying DB.
- `(*Ledger) QuotaBytes()` — configured per-owner quota.
- `(*Ledger) AddOwner(id, owner, size, now) (added, err)` — record a claim or renew
  a lease; enforces quota (the effective ceiling is age-graduated when `QuotaRamp` is
  set — see **Age-graduated quota**). `added` is true only for a new claim (charged
  once); a brand-new owner's first claim also stamps `first_seen`.
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
- `(*Ledger) Entries(filter) (EntriesResult, error)` — browse shard rows (newest
  first) with per-shard owner count + erasure context, filtered server-side by
  shard-ID hex prefix and/or owner key and paginated (`Limit`/`Offset`, with `Total`
  matching rows). Backs the `/admin` ledger browser.
- `(*Ledger) PutStripe(id, k, m, siblings, grant)` — record/replace stripe context.
- `(*Ledger) Stripes() ([]StripeRow, error)` — all stripe contexts (repair loop
  enumerates these).
- `(*Ledger) ColdShards(limit) ([]StripeRow, error)` — up to `limit` stripe contexts
  oldest-stored first, so the rebalancer (Architecture §3.4) offloads its coldest
  shards; the grant on each row authorizes moving the shard to another node.
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
