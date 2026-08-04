# pipeline

The store/retrieve core of revika. This package wires together chunking,
encryption, erasure coding, and the content-addressed store into two reversible
operations: `StoreFile` and `LoadFile`. It is the first end-to-end path — proof
that a file can be split, encrypted, dispersed as shards, and rebuilt from any
K of N — and it runs against any `store.Store` (mock or networked).

## Purpose

- **`StoreFile`** — chunk → compress → encrypt → erasure-code → put shards,
  producing a `FileManifest`.
- **`LoadFile`** — the exact inverse: fetch available shards → erasure-decode →
  decrypt → decompress → write out the original bytes.

Compression is optional and runs *before* encryption (ciphertext is
incompressible); see [`internal/compress`](../compress/README.md).

The `FileManifest` is the recipe to rebuild a file and the only thing (besides
shard access) a reader needs.

## Exported types and functions

- **`Config`** — encoding parameters: `ChunkSize` (plaintext bytes per chunk),
  `Params` (`erasure.Params` giving K data + M parity shards per chunk), and
  `Compress` (DEFLATE each chunk before encrypting).
- **`DefaultConfig() Config`** — sensible defaults: `chunk.DefaultSize` chunks
  with 4+2 erasure coding and compression enabled.
- **`ChunkRef`** — everything needed to rebuild one chunk: its per-chunk
  `crypto.Key`, a `Compressed` flag, and the ordered `[]store.ShardID` content
  addresses of its N shards. Shard index maps directly to erasure position
  (first K are data, the rest parity). `Compressed` is decided per chunk at
  store time (only kept when it shrinks the data), so `LoadFile` relies on the
  flag rather than the `Config`.
- **`FileManifest`** — see below.
- **`StoreFile(ctx, s store.Store, cfg Config, r io.Reader) (FileManifest, error)`**
  — encodes and stores `r`, returning the manifest. Because shards are addressed
  by content hash, identical shards are stored once.
- **`LoadFile(ctx, s store.Store, m FileManifest, w io.Writer) error`** —
  reconstructs the file described by `m` and writes it to `w`, tolerating
  missing shards up to the erasure margin.
- **`StoreBlob(ctx, s, cfg, data []byte) (ChunkRef, error)`** /
  **`LoadBlob(ctx, s, p erasure.Params, ref ChunkRef) (data []byte, error)`** —
  the single-chunk primitive under [`internal/manifest`](../manifest/README.md):
  it runs one blob (a serialized file manifest or directory) through the same
  compress → encrypt → erasure-code → put path and returns a `ChunkRef`, so a
  manifest or directory becomes an immutable, content-addressed, encrypted blob
  that a `ReadCap` can point at. The caller keeps each blob within one chunk.

## FileManifest structure

```go
type FileManifest struct {
    Name   string       // original file name (set by the caller after StoreFile)
    Params Config       // encoding config used (chunk size + K/M + compression)
    Size   int64        // original plaintext size in bytes
    Meta   Metadata     // filesystem attributes (set by the caller after StoreFile)
    Chunks []ChunkRef   // ordered per-chunk recipes (key + compressed flag + shard IDs)
}
```

Each `ChunkRef` carries the chunk's encryption `Key`, its `Compressed` flag, and
its ordered `Shards`.
`StoreFile` takes an `io.Reader` and cannot know the name or on-disk attributes,
so the caller sets `Name` and `Meta` after storing (see `revika-ctl`'s
`runStore`); they let a reader restore the file under its original name and
attributes without being told them out of band.

### Metadata

`Metadata` is the filesystem attribute set carried alongside the chunk recipe so
a stored file round-trips back into a real filesystem and so the **native
cloud-provider frameworks** (macOS `FileProvider.framework`, Windows Cloud Filter
`cldapi`; see [Architecture §3.8](../../Architecture.md)) have every field they
need to present the file as a placeholder without hydrating its shards:

```go
type Metadata struct {
    Mode           uint32            // Go io/fs.FileMode bits (portable type+perm)
    Uid, Gid       uint32            // POSIX owner/group
    ModTimeNS      int64             // mtime  → FP contentModificationDate / CF LastWriteTime
    ChangeTimeNS   int64             // ctime  → CF ChangeTime
    AccessTimeNS   int64             // atime  → FP lastUsedDate / CF LastAccessTime
    BirthTimeNS    int64             // btime  → FP creationDate / CF CreationTime
    Flags          uint32            // cross-platform attribute bits (see Flag*)
    ContentType    string            // IANA MIME type → FP typeIdentifier (advisory)
    SymlinkTarget  string            // non-empty iff a symlink → FP symlinkTargetPath
    Xattr          map[string][]byte // extended attributes → FP extendedAttributes
    ContentVersion []byte            // opaque change tokens matching
    MetaVersion    []byte            //   FP NSFileProviderItemVersion (content + metadata)
}
```

The `Flag*` constants (`FlagHidden`, `FlagReadOnly`, `FlagSystem`, `FlagArchive`)
carry attributes that have no POSIX mode bit but that File Provider / Cloud Filter
express, so a Windows-origin "system" flag survives a round-trip.

`DeriveVersions(&m)` fills the two version tokens deterministically:
`ContentVersion` hashes the ordered shard IDs (changes iff the bytes change) and
`MetaVersion` hashes the attribute fields (changes iff an attribute changes) —
exactly what a native provider needs to tell "renamed" from "re-uploaded"
without fetching a shard.

The stable *item identifier* (FP `itemIdentifier` / CF `FileIdentity`) is
deliberately **not** here: it is a namespace concern owned by the directory
manifest (Architecture §3.6/§3.8), not a property of a file's content. Capturing
`Metadata` from disk and restoring it (chmod/chtimes/chown/setxattr, symlink
recreation) lives in `revika-ctl` (`meta.go` + per-OS `meta_linux.go` /
`meta_other.go`), since it touches the OS; the portable subset (mode, mtime,
content type, symlink, flags) is captured everywhere and the richer POSIX fields
where the platform exposes them.

## How it ties the pieces together

`storeChunk` (per chunk):

1. If `Config.Compress` is set, `compress.Compress` DEFLATEs the plaintext; the
   compressed form is kept only when it is smaller (incompressible data is
   stored verbatim), and the outcome is recorded in `ChunkRef.Compressed`.
2. `crypto.NewKey` mints a fresh per-chunk key; `crypto.Seal` encrypts the
   (possibly compressed) payload.
3. `erasure.Encode` splits the ciphertext into all N shards at once, so every
   shard's content address is known before the first put.
4. It builds a `stripe.Descriptor` (the non-confidential erasure context: K, M,
   and the ordered shard IDs). If the store implements `stripe.Putter` (a
   networked `PlacementStore`) it calls `PutStripe` so each node records the
   descriptor for later repair; otherwise it falls back to `store.Put`. Each
   returned ID is verified against the precomputed content hash.

`loadChunk` (per chunk): fetches each shard, treating `store.ErrNotFound` /
`store.ErrCorrupt` as a lost shard (erasure covers it), then `erasure.Decode`
and `crypto.Open` recover the payload, and `compress.Decompress` restores the
plaintext when `ChunkRef.Compressed` is set.

Chunking comes from `chunk.Fixed`, an iterator over fixed-size plaintext chunks.

## How it fits into revika

This package holds the client-side intelligence: all chunking, key generation,
and encryption happen here before shards leave the machine, while the store sees
only content-addressed ciphertext shards. The `FileManifest` is currently an
in-memory value returned by `StoreFile` and consumed by `LoadFile`;
`revika-ctl` serializes it to local JSON. In the full system a manifest is
itself encrypted and its location + keys form a read-capability for sharing.
