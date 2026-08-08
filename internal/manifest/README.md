# manifest

revika's **cap-addressed metadata layer**: it turns the in-memory
`pipeline.FileManifest` into an immutable, content-addressed, **encrypted blob**,
and builds directories on top as a **Merkle DAG** of such blobs
([Architecture §3.6/§4](../../Architecture.md)). This is the layer the mount/sync
surfaces (§3.7/§3.8) resolve against: file manifest = inode, directory =
namespace, root pointer = mutable superblock.

It reuses the layers below rather than reimplementing them:

- [`internal/pipeline`](../pipeline/README.md) `StoreBlob`/`LoadBlob` — the
  compress → encrypt → erasure-code → store path, now applied to a *single blob*.
- [`internal/cap`](../cap/README.md) `Wrap`/`Unwrap` (ML-KEM-768, FIPS 203) —
  delivering a cap to a recipient when sharing (§3.5).

Nodes still see only content-addressed ciphertext shards; the whole namespace
(names, tree shape, sizes) is encrypted client-side.

## The pivot: `ReadCap`

A `ReadCap` is the minimal, self-contained recipe to fetch and decrypt **one**
blob — a per-blob AES-256 key plus the ordered content addresses of its erasure
shards, tagged with a `Kind` (`KindFile` | `KindDir`):

```go
type ReadCap struct {
    Kind       Kind            // file manifest or directory
    Key        crypto.Key      // per-blob AES-256 key
    Compressed bool            // blob plaintext was DEFLATEd before encryption
    K, M       int             // erasure parameters
    Shards     []store.ShardID // ordered content addresses (K data + M parity)
}
```

A `ReadCap` **is** a file's (or directory's) read-capability: whoever holds it
can rebuild that blob and nothing else. Because it carries content-addressed
shard IDs, it **commits to the blob's exact bytes** — so a directory cap (whose
blob lists its children's caps) transitively commits to every descendant. A
parent cap is thus a **Merkle root over its subtree**, and the namespace is a DAG
of encrypted blobs anchored by one signed `RootPointer`.

## The cap-derivation chain: `WriteCap → ReadCap → VerifyCap`

Each level derives from the one above but never the one below, so you delegate
exactly the privilege you intend (Architecture §3.5):

- **`WriteCap = cap.SignKey`** (alias) — the Ed25519 signing key; the sole
  authority to advance the `RootPointer`. Read + write.
- **`ReadCap`** — read only: the per-blob AES key + shard content addresses.
- **`VerifyCap = ReadCap.VerifyCap()`** — the read-cap **minus its AES key**: it
  still locates and integrity-checks a blob's shards but cannot decrypt.
  `manifest.VerifyBlob(ctx, s, v)` fetches the shards by content address and
  confirms ≥ K are recoverable — repair and health probes attest a subtree
  without ever holding the read key. `VerifyCap.ReadCap()` re-embeds a **zero**
  key, so the downgrade is one-way (you can never turn a verify-cap back into a
  decrypting read-cap).

The public DHT root record carries only the verify projection. A `RootPointer`
signs over `Root.VerifyCap().ReadCap().MarshalBinary()`, so the **identical
signature** validates both the local full-key pointer and the key-stripped one
published to the network — the reader's secret AES key never enters the digest.

## Naming is a namespace concern

A file blob is **nameless** — addressed only by content. Its name lives in the
parent directory's `Entry`. Renaming rewrites one directory blob (copy-on-write,
`Graft`) and **never touches — nor changes the address of — the file blob**. This
is why naming belongs to the directory: making a mutable label part of a
content-addressed blob would force needless rewrites on every rename.

| Fact | Lives in | Mutable? |
|---|---|---|
| chunk keys, shard IDs, size, mode/times | file manifest blob | no (content-addressed) |
| a child's name + its slot in the tree | parent directory blob | yes (COW rewrite) |
| latest root of the tree | signed `RootPointer` | yes (`Seq++`) |

## Types and functions

### Blobs & caps
- **`ReadCap`** — the read-capability (above). `MarshalJSON`/`MarshalBinary`
  render it with hex key + shard IDs; `Params()` returns its `erasure.Params`.
- **`WrapCap(recipient cap.PublicKey, c ReadCap) ([]byte, error)`** /
  **`UnwrapCap(priv, pub, sealed) (ReadCap, error)`** — seal a cap to a
  recipient's ML-KEM-768 key. Sharing a **directory** cap grants read access to
  that subtree and everything reachable from it — no more, no less (§3.5).

### Files
- **`StoreFileManifest(ctx, s, cfg, m pipeline.FileManifest) (ReadCap, error)`** —
  serialize a file manifest and store it as a `KindFile` blob.
- **`LoadFileManifest(ctx, s, c ReadCap) (pipeline.FileManifest, error)`** — the
  inverse; feed the result to `pipeline.LoadFile` to get the file's bytes.
- **`EncodeFileManifest`/`DecodeFileManifest`** — the canonical JSON codec
  (shared shape with `revika-ctl`'s on-disk manifest, which this supersedes).

### Directories
- **`DirManifest`** — a directory: its own `Meta` plus name-sorted `Entries`
  (each an `Entry{Name, Cap, Stat}`). `NewDir`, `Lookup`, `Upsert`, `Remove` are
  copy-returning (never mutate a shared directory in place).
- **`StatCache`** — the small snapshot a directory keeps per child (kind, size,
  mode, mtime, version tokens) so a mount serves `readdir`/`getattr` **without
  hydrating** the child (the placeholder model, §3.8).
- **`StoreDir`/`LoadDir`**, **`EncodeDir`/`DecodeDir`** — store/load a directory
  blob; encoding is canonical (entries sorted, so the same content → same bytes).
- **`Resolve(ctx, s, root ReadCap, path) (ReadCap, error)`** — walk a
  slash-separated path from a root dir cap to a target cap. `..` is rejected (a
  DAG has no parent-of-root). Only `open`/`read` on the returned cap touches the
  network beyond the directories on the path — on-demand hydration.
- **`ResolveEntry(ctx, s, root ReadCap, path) (Entry, error)`** — like `Resolve`
  but returns the target's directory `Entry` (cap **plus** the parent's cached
  `StatCache`), so a caller can copy a node preserving its size/mode/mtime. The
  root itself (empty path) is reported as a nameless `KindDir` entry. Backs the
  `revika-ctl cp rvk:a rvk:b` in-namespace copy: graft the resolved cap at a new
  path (CoW), and the two paths share shards by content address.
- **`Graft(ctx, s, cfg, root, path, child, stat) (ReadCap, error)`** — the
  **copy-on-write** mutation primitive: bind `child` at `path`, rewriting every
  directory on the path → a new root. Untouched sibling subtrees keep their caps
  and shards. Missing intermediate directories are created. Backs put/rename.
- **`GraftRemove(ctx, s, cfg, root, path) (ReadCap, error)`** — COW delete.

### Revocation
- **`Rekey(ctx, s, cfg, root ReadCap, subpath) (ReadCap, error)`** — re-encrypt the
  subtree at `subpath` under **fresh keys**, down to the data chunks
  (`pipeline.ReencryptFile` for files; `StoreDir`/`StoreFileManifest` mint fresh
  blob keys per call), then `Graft` it back into a new root (CoW — siblings and
  their shards untouched; empty `subpath` rekeys the whole namespace). A previously
  shared cap named the *old* shard IDs, so once the bytes move to new content
  addresses that cap can no longer locate them. The caller then advances the
  `RootPointer` and reclaims the orphaned old shards. Needs **read access** (it
  decrypts + re-encrypts), so a sign-key-only holder cannot rekey. Cost is
  O(subtree bytes). This revokes *future* reads only — it cannot claw back bytes a
  recipient already downloaded. Driven by `revika-ctl revoke rvk:<path>`.

### Root pointer (§4)
- **`RootPointer{Owner, Root, Seq, TimeNS, Sig}`** — the one mutable anchor per
  User: a signed `owner-pubkey → root cap` record with a monotonic `Seq`.
- **`SignRoot(k cap.SignKey, root ReadCap, seq, timeNS) (RootPointer, error)`** /
  **`(RootPointer).Verify() bool`** — Ed25519 sign/verify over a domain-separated
  payload committing to the cap's **verify projection** (so the same signature holds
  for the local full-key pointer and the key-stripped DHT record). Readers keep the
  highest verified `Seq` (anti-rollback). This package takes no clock — `timeNS` is
  supplied by the caller — so it stays deterministic. Publishing/resolving the
  pointer over the network lives in [`internal/net`](../net/README.md) (`PutRoot`/
  `GetRoot` + the `/revika/root` stream) and [`internal/provider`](../provider/README.md)
  (`DHTRootStore`/`MultiRootStore`).

### Multi-device reconciliation (§3.7.1)
- **`Merge3(ctx, s, cfg, base, local, remote ReadCap, label MergeLabeler) (ReadCap, []string, error)`**
  (`merge.go`) — three-way merge of two divergent roots over the COW DAG. Cap-equality
  prunes unchanged subtrees whole; only genuine divergence is descended. A leaf both sides
  changed differently keeps the local edit under its name and files the remote as a **conflict
  copy** via `label` (returned in the `[]string` slash-paths); a delete racing an edit keeps
  the edit. Content-complete and structurally deterministic, **not** cap-identical across runs
  (`StoreDir` mints a fresh per-blob key) — convergence comes from the caller's monotonic `Seq`,
  not cap identity. `DefaultLabeler` is the untagged fallback; the CLI injects a device-tagged one.
- **`FullRootRecord{Owner, Seq, Sealed, Seals, Sig}`** (`fullroot.go`) — the **sealed self-root
  companion** that delivers the decryptable root between a User's own devices. `SealFullRoot(signer,
  recipient, root, seq)` wraps the *full* root cap (AES key retained) to the owner's own ML-KEM
  key (`WrapCap`) and Ed25519-signs `owner||seq||sealed` under a distinct domain tag; `Open(priv,
  pub)` verifies then `UnwrapCap`s it. Confidentiality rests on the ML-KEM seal (only owner devices
  hold the key); the caller binds `companion.VerifyCap() == verifyRoot.Root` for the monotonic
  `Seq`. Published/resolved over the DHT by `net.PutFullRoot`/`GetFullRoot` under `/revika-fullcap`.
  For the **read-revocable device model** (Architecture §3.7.2) `SealFullRootFor(signer, recipients,
  root, seq)` seals **one copy per authorized device** into `Seals` (the signature covers them when
  non-empty), so revoking a device = resealing to the survivors. `Open` tries the legacy single-owner
  `Sealed` first, then each `Seals` entry, returning `ErrNoSealForKey` when none fit — a revoked
  device's key. A workspace that never ran `device init` keeps producing legacy `Sealed`-only records,
  byte-identical to before, so old readers are unaffected.

## Blob size budget (and the scale path)

A blob is a **single erasure chunk** (`pipeline.StoreBlob` does not sub-chunk),
so a serialized manifest or directory must fit in one `Config.ChunkSize` (4 MiB
by default — roughly ~16k directory entries, or a ~75 GiB file's chunk list).
Sharding a large directory into an internal DAG (HAMT/B-tree), so a single-entry
change rewrites `O(log n)` blobs instead of the whole directory, is the
documented scale path (§3.6); the PoC keeps **one blob per directory**.

## Copy-on-write, end to end

Editing a file → new file-manifest blob → new cap → `Graft` replaces that entry
in the parent → new directory blob → … → new root cap → `SignRoot` advances the
`RootPointer` (`Seq+1`). Only the path from the changed node to the root is
rewritten; every sibling subtree is shared by reference. Free versioning, one
mutable anchor, and a node cannot serve a rolled-back root (lower `Seq`).

## Driving it from the CLI

`revika-ctl cp <dir> rvk:<path>` walks a filesystem directory and builds the tree
with this package — each file becomes a `KindFile` manifest blob, each folder a
`KindDir` blob, grafted together copy-on-write — then `Graft`s it into the User's
namespace under `<path>` and `SignRoot`s an advanced `RootPointer`, persisted to
the `-root` file (default `.revika/root.json`). `cp rvk:<path> <dir>` resolves the
path and materializes the file or whole subtree, restoring files, symlinks,
sub-directories, empty directories, and per-entry metadata
(`cmd/revika-ctl/tree.go`). Because it runs entirely through
`pipeline.StoreBlob`/`LoadBlob` → `store.Put`/`Get`, it works unchanged over a
single node or a DHT-spread network. `ls rvk:<path>` browses via `LoadDir`,
fetching **only directory blobs** (no file content) — the `readdir`/`stat` half of
the on-demand model (Architecture §3.8).

Sharing composes directly on `Resolve` + a signed, sealed `RootPointer`:
`revika-ctl share rvk:<subpath> -to <pubkey>` resolves the subpath to a child
`ReadCap`, wraps it in a `RootPointer` anchored there, signs it, and seals it to
the recipient's ML-KEM-768 key — so you hand over a single file or one
subdirectory of a stored tree, granting exactly that subtree and nothing outside
it. The recipient uses the sealed file as their `-root` (opened with `-key`) and,
reading the cap's `Kind`, `ls`/`cp` restore either the single file or the subtree.
Covered in-process by `cmd/revika-ctl/namespace_e2e_test.go` (`TestNamespaceE2E`)
and over a live multi-node network by `deploy/tree.sh` (docker-compose profile
`tree`).
