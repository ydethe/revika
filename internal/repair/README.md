# repair

Keeps stored data durable. Erasure coding alone only *delays* data loss: as
shards disappear (nodes leave, disks die), every chunk drifts toward the point
where fewer than `K` shards remain and the data is gone forever. This package is
the maintenance loop that pushes back — it probes which shards survive and
regenerates the missing ones while enough remain to reconstruct.

## Why repair is ciphertext-only

Two properties keep repair clean and confidential:

- **No decryption key needed.** Repair operates purely on the encrypted,
  erasure-coded shards. In capability terms it needs only a verify-cap, never
  the encryption key — so untrusted nodes (or any repair worker) can heal data
  without ever seeing plaintext.
- **Deterministic re-encode.** `erasure.Encode` is deterministic, so a
  regenerated shard reproduces its *exact* content address. Repair restores the
  same shard IDs recorded in the manifest, so the manifest never changes. The
  regenerated address is asserted against the manifest's recorded ID; a mismatch
  is treated as an error (a signal of non-deterministic encoding).

## Exported API

### Types

- **`ChunkStatus`** — shard availability of a single chunk: `Index`, `Present`
  (shards currently in the store), `Total` (N = K + M), and `Missing` (positions
  absent from the store).
  - `Recoverable(k int) bool` — true if at least `k` shards are present.
  - `Healthy() bool` — true if no shards are missing.
- **`Report`** — availability of every chunk in a file (`Chunks []ChunkStatus`).
  - `Healthy() bool` — true if every chunk has all shards present.
  - `MissingShards() int` — total absent shards across all chunks.

### Functions

- **`Check(ctx, s store.Store, m pipeline.FileManifest) (Report, error)`** —
  probes shard availability for every chunk via `store.Has`, without moving any
  data. Returns a `Report`. The strength of a "present" verdict is the store's:
  over a plain `NetStore`/`DHTStore` it trusts the holder's presence byte, but
  over a `net.RepairStore` with possession-verify enabled (`SetVerifyPossession`,
  `revika-node -repair-verify`) each remote `Has` becomes a proof of retrieval
  (fetch + self-verify `hash == ID`), so a node lying about holding a shard is
  caught and the shard counts as missing.
- **`Repair(ctx, s store.Store, m pipeline.FileManifest) (Report, error)`** —
  regenerates missing shards for every chunk that is still recoverable
  (`>= K` shards present), restoring each to full redundancy. Chunks that have
  dropped below `K` are unrecoverable; they are reported via a joined error, but
  every other chunk is still repaired. Returns a fresh post-repair `Report`.

## How a chunk is repaired

For each chunk (`repairChunk`, unexported):

1. Fetch every surviving shard with `store.Get`, recording which positions are
   missing *before* decoding (Reed–Solomon reconstruction fills gaps in place,
   so the missing set cannot be inferred afterward). `ErrNotFound` and
   `ErrCorrupt` count a shard as missing.
2. If nothing is missing, the chunk is already whole — skip it.
3. If fewer than `K` shards are present, the chunk is unrecoverable — return an
   error.
4. Otherwise `erasure.Decode` recovers the still-encrypted payload,
   `erasure.Encode` deterministically re-encodes it, and each missing shard is
   `Put` back into the store. The returned content address is checked against
   the manifest's recorded shard ID.

## Fit within revika

Repair is **mandatory** in revika's design: erasure coding without repair only
postpones data loss. Because it works on ciphertext addressed by content hash
and reproduces the original shard IDs, repair can run as a background process on
nodes (see `internal/net`'s repair store and `cmd/revika-node`'s `-repair`
loop) without any access to user keys or plaintext.
