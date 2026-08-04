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
- **`Graft(ctx, s, cfg, root, path, child, stat) (ReadCap, error)`** — the
  **copy-on-write** mutation primitive: bind `child` at `path`, rewriting every
  directory on the path → a new root. Untouched sibling subtrees keep their caps
  and shards. Missing intermediate directories are created. Backs put/rename.
- **`GraftRemove(ctx, s, cfg, root, path) (ReadCap, error)`** — COW delete.

### Root pointer (§4)
- **`RootPointer{Owner, Root, Seq, TimeNS, Sig}`** — the one mutable anchor per
  User: a signed `owner-pubkey → root cap` record with a monotonic `Seq`.
- **`SignRoot(k cap.SignKey, root ReadCap, seq, timeNS) (RootPointer, error)`** /
  **`(RootPointer).Verify() bool`** — Ed25519 sign/verify over a domain-separated
  payload. Readers keep the highest verified `Seq` (anti-rollback). This package
  takes no clock — `timeNS` is supplied by the caller — so it stays deterministic.

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

`revika-ctl put -r <dir>` walks a filesystem directory and builds the tree with
this package — each file becomes a `KindFile` manifest blob, each folder a
`KindDir` blob, grafted together copy-on-write — then writes the root directory
cap to `-manifest` (the tree's read-capability). `get -r -o <dir>` resolves that
root cap and materializes the whole tree, restoring files, symlinks,
sub-directories, empty directories, and per-entry metadata
(`cmd/revika-ctl/tree.go`). Because it runs entirely through
`pipeline.StoreBlob`/`LoadBlob` → `store.Put`/`Get`, it works unchanged over a
single node or a DHT-spread network.

Sharing composes directly on `Resolve` + `WrapCap`: `revika-ctl share -manifest
<root-cap> -path <subpath> -to <pubkey>` resolves the subpath to a child
`ReadCap` and wraps *that* (not the root) to the recipient — so you hand over a
single file or one subdirectory of a stored tree, granting exactly that subtree
and nothing outside it. `get -cap <file> -key <priv>` unwraps it and, reading the
cap's `Kind`, restores either the single file or (with `-o <dir>`) the subtree;
sharing a whole file manifest or the whole root cap works the same way without
`-path`. Covered in-process by `cmd/revika-ctl/tree_test.go`
(`TestShareGetSubpath`) and over a live multi-node network by `deploy/tree.sh`
(docker-compose profile `tree`).

Lazy materialization uses the same primitives (`cmd/revika-ctl/sync.go`,
Architecture §3.8): `revika-ctl sync` walks the DAG via `LoadDir` fetching **only
directory blobs**, recreating the namespace as folders + symlinks + empty file
placeholders and writing a `.revika-sync.json` index of each placeholder's
`ReadCap`; `revika-ctl hydrate <path>` then `LoadFileManifest`s just the wanted
files and fetches their shards. `sync` is the `readdir`-time placeholder build
and `hydrate` the `open`/`read` fetch of §3.8, driven explicitly from the CLI.
Because the index stores `ReadCap`s (decryption keys), `sync`/`hydrate` write it
`0600`. Covered in-process by `cmd/revika-ctl/sync_test.go`.
