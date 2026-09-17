# CloudStorage.md — the revika daemon & OS cloud-storage integration

Specification, API reference, and implementation guidelines for **`revika-daemon`** and its
OS filesystem-integration surface. This is the document to build against when the daemon is
implemented; it makes concrete what [Architecture.md](../Architecture.md) §1/§3.7/§3.8 describes.

- **Status of the code today:** the framework-neutral provider contract (`internal/provider`),
  sync-anchor types, initial pure-Go storage foundations, immutable content-addressed manifest
  nodes, a signed-root snapshot-backed provider, and an in-memory reference provider are
  implemented. Vector clocks, a deterministic text CRDT, provider-neutral placement/repair, and
  the generic daemon lifecycle coordinator are also implemented. The metadata
  bridge (`internal/fsmeta`) and daemon
  binary (`cmd/revika-daemon`), the sync engine (`internal/sync`), and the FUSE PoC
  (`internal/mount`) remain planned. The DHT-backed `RootStore`, network adapters, and per-OS
  native bindings are excluded from this implementation phase — this document is their contract.
- **Audience:** whoever implements the daemon, the mount, or a per-OS binding shim.
- **Non-goals:** node-side behaviour (see Architecture §3.2), the crypto/erasure pipeline
  (§3.3), and sharing (§3.5) are covered elsewhere and only referenced here.

---

## 1. What the daemon is

`revika-daemon` is the **User-side background service**: it presents the user's encrypted,
erasure-coded, network-resident namespace as an ordinary-looking local filesystem, with
on-demand hydration ("files on demand"). It is the counterpart to `revika-node` (the
headless blob server) and may optionally run a node in-process (Architecture §1).

It offers **two complementary surfaces over the same metadata layer** (§3.6), never
alternatives:

| Surface | What the user sees | Backed by |
|---|---|---|
| **Sync** (§3.7) | a plain local folder, mirrored both ways | `internal/sync` (planned) |
| **Mount** (§3.8) | a mounted filesystem with placeholders + hydration | `internal/mount` (FUSE PoC) → native bindings |

Both resolve against the **same core**: the `provider.Provider` API. The daemon's job is to
(a) own a long-lived `Provider` instance per mounted domain, (b) drive it from either a
folder watcher (sync) or the OS's cloud-provider callbacks (mount), and (c) keep the
network plumbing (libp2p host, DHT, node connections) alive underneath.

```
┌──────────────────────────────────────────────────────────────┐
│  OS cloud framework   │   folder watcher    │   FUSE kernel    │   ← surface drivers
│  (File Provider /     │   (fsnotify)        │   (go-fuse)      │
│   Cloud Filter / GVfs)│                     │                  │
└───────────┬───────────┴──────────┬──────────┴────────┬─────────┘
            │  native callbacks    │  local diffs       │  VFS ops
            ▼                       ▼                    ▼
        ┌───────────────────────────────────────────────────┐
        │            provider.Provider  (this API)            │   ← framework-neutral core
        │   Manifest impl: Merkle-DAG resolve + COW mutate    │
        └───────────────┬─────────────────────┬───────────────┘
                        │ manifest DAG          │ RootStore (root pointer)
                        ▼                       ▼
                internal/manifest        DHT / local  (§4)
                internal/pipeline        publication
```

---

## 2. The core API — `internal/provider`

The three native cloud frameworks (macOS **File Provider**, Windows **Cloud Filter**, Linux
**GVfs/GIO**) speak different dialects but require the **same shape**. `provider.Provider`
is that shape, expressed once in pure Go so a single core serves all of them. Nothing in the
package touches an OS API, so it builds and tests on every platform; a per-OS binding layer
(§5) translates native callbacks into these calls.

### 2.1 Interface

```go
type Provider interface {
    Root(ctx context.Context) (ItemID, error)

    Stat(ctx context.Context, id ItemID) (Item, error)
    Lookup(ctx context.Context, parent ItemID, name string) (Item, error)
    Enumerate(ctx context.Context, dir ItemID) ([]Item, error)

    CurrentAnchor(ctx context.Context) (SyncAnchor, error)
    EnumerateChanges(ctx context.Context, since SyncAnchor) (ChangeSet, error)

    FetchContents(ctx context.Context, id ItemID, w io.Writer) (ItemVersion, error)
    Evict(ctx context.Context, id ItemID) error

    CreateItem(ctx context.Context, parent ItemID, req CreateRequest) (Item, error)
    ModifyItem(ctx context.Context, id ItemID, req ModifyRequest) (Item, error)
    DeleteItem(ctx context.Context, id ItemID) error
    Rename(ctx context.Context, id ItemID, newParent ItemID, newName string) (Item, error)
}
```

All methods are **safe for concurrent use**. The default implementation, `provider.Manifest`,
serializes mutations on an internal mutex while reads take a lock-free snapshot of the current
root cap.

### 2.2 Mapping to native callbacks

| `Provider` method | macOS File Provider | Windows Cloud Filter | Linux GVfs/VFS |
|---|---|---|---|
| `Root`             | `.rootContainer` identifier   | Sync Root registration          | mount root      |
| `Stat`             | `item(for:)`                  | getattr / basic info            | `query_info`    |
| `Lookup`           | (enumerator match)            | `FETCH_PLACEHOLDERS` (one)      | `lookup`        |
| `Enumerate`        | `enumerateItems(for:)`        | `FETCH_PLACEHOLDERS`            | `enumerate`     |
| `EnumerateChanges` | `enumerateChanges(from:)`     | in-sync / drift reconcile       | poll + diff     |
| `CurrentAnchor`    | `currentSyncAnchor`           | USN cursor                      | etag            |
| `FetchContents`    | `fetchContents(for:)`         | `FETCH_DATA`                    | `open` + `read` |
| `Evict`            | `evictItem(identifier:)`      | `CfUpdatePlaceholder(DEHYDRATE)`| drop cache      |
| `CreateItem`       | `createItem(basedOn:)`        | upload + `CfCreatePlaceholders` | `create`/`mkdir`|
| `ModifyItem`       | `modifyItem(_:changedFields:)`| sync-out changed data           | `write`/`setattr`|
| `DeleteItem`       | `deleteItem(identifier:)`     | delete sync                     | `delete`/`rmdir`|
| `Rename`           | `modifyItem`(parent/filename) | rename sync                     | `move`/`set_name`|

### 2.3 Types

```go
type ItemID string           // opaque, stable across rename/move
const RootID ItemID = "root"  // the mount point / root container

type ItemVersion struct {     // NSFileProviderItemVersion / CF drift tokens
    Content []byte            // changes iff the bytes change
    Meta    []byte            // changes iff an attribute changes
}

type Capabilities uint32
const (
    CapRead Capabilities = 1 << iota
    CapWrite
    CapRename
    CapReparent
    CapDelete
    CapAddSubItems   // directories only
    CapEnumerate     // directories only
)
func (caps Capabilities) Has(c Capabilities) bool

type Item struct {            // placeholder-ready description (no content needed)
    ID      ItemID
    Parent  ItemID
    Name    string
    IsDir   bool
    IsLink  bool
    Size    int64
    Version ItemVersion
    Meta    pipeline.Metadata // full record from Stat; light subset (mode+mtime) from Enumerate
    Caps    Capabilities
    Cap     manifest.ReadCap  // the underlying read-capability (for fetch/share)
}

type CreateRequest struct {
    Name     string
    IsDir    bool
    Meta     pipeline.Metadata // Meta.SymlinkTarget set ⇒ a symlink; Contents ignored
    Contents io.Reader         // read to completion for a regular file
}

type ModifyRequest struct {   // nil Contents = metadata-only; nil Meta = content-only
    Contents io.Reader
    Meta     *pipeline.Metadata
}

type ChangeType int
const ( ChangeAdded ChangeType = iota; ChangeModified; ChangeDeleted )

type Change struct {
    Type ChangeType
    ID   ItemID
    Path string   // current slash path (logging / binding placeholder mapping)
    Item *Item    // nil for ChangeDeleted
}

type ChangeSet struct {
    Changes []Change
    Anchor  SyncAnchor  // fresh cursor to pass next time
}
```

`pipeline.Metadata` is the platform-neutral attribute record — `Mode`, `Uid/Gid`, the four
times (`ModTimeNS`/`ChangeTimeNS`/`AccessTimeNS`/`BirthTimeNS`), `Flags`, `ContentType`,
`SymlinkTarget`, `Xattr`, and the version tokens. All times are Unix ns; a zero time means
"not captured on this platform" and is skipped on restore. `internal/fsmeta.Capture` /
`Restore` / `RestoreSymlink` bridge it to and from a live on-disk file.

### 2.4 Method semantics (the contract a binding relies on)

- **`Stat`** returns the *full* metadata record by reading the item's own blob. **`Enumerate`**
  returns a *light* record (mode + mtime cached in the parent directory) so a listing touches
  no file content. Bindings that need full attributes for a listed child must `Stat` it.
- **`FetchContents`** streams the item's bytes to `w` (on-demand hydration) and returns the
  `ItemVersion` it served, so the binding can stamp the materialized file. A **symlink** has no
  shard bytes — nothing is written; read `Meta.SymlinkTarget` from `Stat`.
- **`Evict`** signals that local content may be dropped. The manifest backing keeps no local
  copy (content is remote by nature), so it is a **no-op** there; a mount that maintains a
  placeholder cache overrides `Evict` to drop cached bytes.
- **`CreateItem` / `ModifyItem` / `DeleteItem` / `Rename`** each perform one copy-on-write
  mutation and publish a new signed root (§3). They return the resulting `Item` (except
  `DeleteItem`). A no-op `ModifyItem` (both fields nil) returns the current `Stat` without
  publishing.
- **`Rename`** keeps the `ID` stable across rename *and* reparent (pass a different `newParent`
  to move). It re-grafts the **same content-addressed child cap** at the destination, so shards
  and versions are untouched — only two directory blobs are rewritten.
- **Not-found** surfaces as the sentinel `provider.ErrNotFound`; bindings map it to the
  framework's no-such-item error (see §5.4).

### 2.5 What backs it — `provider.Manifest`

```go
func New(ctx context.Context, s store.Store, signer cap.SignKey, roots RootStore,
         opts ...Option) (*Manifest, error)

func WithConfig(cfg pipeline.Config) Option // encoding params for blobs it writes
func WithClock(fn func() int64) Option      // RootPointer timestamp source (Unix ns)
```

`Manifest` resolves every call against the cap-addressed **Merkle DAG** (`internal/manifest`)
over any `store.Store`:

- reads load directory / file-manifest blobs;
- `FetchContents` runs `pipeline.LoadFile`;
- each mutation is a `manifest.Graft` / `GraftRemove` — copy-on-write up the tree to a new
  root — followed by a `commit` that signs a new `RootPointer` and persists it via `RootStore`.

`New` adopts an existing root pointer from `roots` (verifying its signature and that its
`Owner == signer.Public()`) or bootstraps an empty root directory published at sequence 1.

Nodes still see only content-addressed ciphertext shards; **all** naming, tree shape,
versioning, and identity live on the User side here.

---

## 3. Identity, versions, anchors — the three cross-cutting concerns

### 3.1 Stable item identity

The frameworks require an identifier **stable across renames and moves** (File Provider
`itemIdentifier`, Cloud Filter `FileIdentity`). A content cap is *not* that — it is stable
across rename but changes on every edit. So identity is owned by the provider (`identity.go`):
it is the **sole mutator** of its domain, so it maintains an authoritative path⇄`ItemID` map
and re-keys it on `Rename` (prefix-aware, so a moved directory carries its whole subtree's IDs)
and retires IDs on `Delete` (a later recreation under the same name is a *new* item with a fresh
ID — matching framework semantics).

- `ItemID` is **opaque**: bindings must persist and echo it, never parse or derive it.
- `RootID` (`"root"`) is fixed and maps to the framework's root container.
- **Persistence caveat (daemon TODO):** the current map is in-memory, so IDs are stable only
  within a process lifetime. A daemon that must survive restarts needs to persist the map (or a
  seed for it) alongside the mount state — see §6.4. A future intrinsic `manifest.Entry.ID`
  (Architecture §3.6) would remove this concern.

### 3.2 Versions

`ItemVersion{Content, Meta}` lets a framework tell "same content, new name" from "new content"
**without downloading a shard**. `pipeline.DeriveVersions` computes both deterministically:
`Content` hashes the ordered shard IDs (changes iff bytes change); `Meta` hashes the attribute
fields (changes iff an attribute changes). Directories derive `Content` from the blob cap (which
commits to the whole subtree). Bindings map this pair to `NSFileProviderItemVersion`
(contentVersion + metadataVersion) and to Cloud Filter drift detection.

### 3.3 Anchors & change enumeration

```go
type SyncAnchor struct {           // opaque cursor: root cap at a sequence
    Seq  uint64
    Root manifest.ReadCap
}
func (a SyncAnchor) Bytes() []byte             // serialize for framework storage
func ParseAnchor(b []byte) (SyncAnchor, error) // reverse
```

`CurrentAnchor` returns the cursor naming the domain's current state; `EnumerateChanges(since)`
returns every add / modify / delete since that cursor plus a fresh anchor. It **diffs two root
caps over the DAG** (`diff.go`): two equal caps address an identical subtree, so **cap equality
prunes whole unchanged branches** unread — diff cost is proportional to what changed, not to the
namespace size. `since.Root` may be the zero cap (sync-from-empty), yielding all-adds.

Bindings serialize the anchor with `Bytes()` and hand it to the framework's opaque cursor slot
(File Provider `NSFileProviderSyncAnchor`, Cloud Filter USN); on the next poll they restore it
with `ParseAnchor` and call `EnumerateChanges`.

---

## 4. The one un-networked seam — `RootStore`

Advancing the namespace means publishing a new **signed `RootPointer`** — the single mutable
anchor per User (Architecture §4). Persisting/publishing it is the only piece of the mount stack
not yet networked, so it is isolated behind an interface:

```go
type RootStore interface {
    Load(ctx context.Context) (rp manifest.RootPointer, ok bool, err error)
    Save(ctx context.Context, rp manifest.RootPointer) error
}
```

- **`MemRootStore`** (implemented) — in-memory, with the **anti-rollback** rule a networked
  store must enforce: reject a `Save` whose `Seq` does not advance the stored one. Good for
  tests and a single-process mount.
- **DHT-backed `RootStore`** (planned, §4/§6 of Architecture) — publishes the pointer
  IPNS-style on the private `/revika` DHT so the namespace is multi-device and network-visible.
  Dropping this in is the **only** change needed to go from single-process to networked; the
  `Provider` API is unchanged.

> **Implementation guideline.** The daemon should treat `RootStore` as its persistence boundary.
> A local-first daemon can start with a **disk-backed** `RootStore` (the signed pointer written
> `0600` to `.revika/root.json`, as `provider.FileRootStore` already does since the pointer names
> the root cap that unlocks the whole namespace) and layer DHT publish on top later — a
> `RootStore` that writes locally *and* publishes, reconciling by highest valid `Seq` on `Load`.

---

## 5. Per-OS binding guidelines

A binding is a thin, per-OS shim that (a) registers the sync root with the OS, (b) receives
native callbacks, and (c) translates them into `Provider` calls, mapping types both ways. Native
bindings are outside this implementation phase and are not dependencies of the generic Go module.
If introduced later, they must remain separate from the cgo-free core and contain only translation
logic. Architecture §3.8 marks these deferred behind the FUSE PoC.

### 5.1 FUSE — the cross-platform PoC first (`internal/mount`, planned)

Pure Go via `hanwen/go-fuse`; the fastest path to a working mount from one codebase and the
reference the native bindings are validated against.

| VFS op | `Provider` call |
|---|---|
| `lookup`            | `Lookup(parent, name)` |
| `getattr`           | `Stat(id)` → `Meta` + `Size` |
| `readdir`           | `Enumerate(dir)` |
| `open`+`read`       | `FetchContents(id, w)` (cache to a temp file; serve reads from it) |
| `create`/`mkdir`/`symlink` | `CreateItem(parent, req)` |
| `write`+`flush`     | buffer, then `ModifyItem(id, {Contents})` on flush/close |
| `setattr`           | `ModifyItem(id, {Meta})` |
| `unlink`/`rmdir`    | `DeleteItem(id)` |
| `rename`            | `Rename(id, newParent, newName)` |

FUSE exposes a classic mountpoint, **not** the placeholder/sync-badge UX — that is the native
frameworks' job. Note macFUSE is a PoC vehicle only (Apple is locking down kernel extensions),
not the long-term macOS surface.

### 5.2 macOS — File Provider (`NSFileProviderReplicatedExtension`)

- Register a domain; implement the replicated-extension protocol. `item(for:)`→`Stat`,
  `enumerateItems`→`Enumerate`, `enumerateChanges(from:)`→`EnumerateChanges`,
  `fetchContents`→`FetchContents`, `createItem`/`modifyItem`/`deleteItem`→the mutations.
- Map `Item.Version` → `NSFileProviderItemVersion(contentVersion:metadataVersion:)`;
  `Item.Caps` → `NSFileProviderItemCapabilities`; `Meta.SymlinkTarget` → `symlinkTargetPath`.
- `modifyItem(changedFields:)` splits into `ModifyItem` (content/attributes) vs `Rename`
  (parentItemIdentifier / filename) — mirror the field mask.
- Anchor: `SyncAnchor.Bytes()` ⇄ `NSFileProviderSyncAnchor`.

### 5.3 Windows — Cloud Filter API (`cldapi.dll`, Sync Root)

- Register a sync root; create placeholders from `Enumerate` (`CfCreatePlaceholders` with
  `FILE_BASIC_INFO` from `Meta` + `Size`). Hydration: `FETCH_DATA` callback → `FetchContents`.
  Dehydration: `CfUpdatePlaceholder(...DEHYDRATE)` ↔ `Evict`.
- Drive out local edits (in-sync/drift) via `ModifyItem`/`Rename`/`DeleteItem`; detect drift
  with the `ItemVersion` tokens; walk remote changes with `EnumerateChanges` over a USN cursor
  seeded from `SyncAnchor.Bytes()`.
- `FileIdentity` blob = `ItemID` bytes (opaque; store and echo).

### 5.4 Linux — GVfs/GIO (or KIO)

- Implement a GVfs backend: `query_info`→`Stat`, `enumerate`→`Enumerate`, `open`/`read`→
  `FetchContents`, `create`/`delete`/`set_display_name`/`move`→the mutations. No first-class
  placeholder API — poll `EnumerateChanges` and reflect deltas.

### 5.5 Error mapping (all bindings)

| `Provider` error | map to |
|---|---|
| `provider.ErrNotFound` | File Provider `noSuchItem` / Win `ERROR_NOT_FOUND` / GIO `G_IO_ERROR_NOT_FOUND` |
| `RootStore` anti-rollback (`Seq` did not advance) | transient conflict — refetch anchor, retry |
| context cancelled / deadline | framework's cancellation/timeout error |
| other | framework's generic I/O error; log with the `Change.Path`/`ItemID` for triage |

---

## 6. Implementing the daemon

### 6.1 Binary & lifecycle (`cmd/revika-daemon`, planned)

Responsibilities:

1. **Load keys** — the User ML-KEM keypair (receiving shares) and the Ed25519 signing identity
   (the storage owner; self-certifying via PoW, `internal/cap/pow.go`). `signer` for the
   `Provider` comes from the Ed25519 key.
2. **Stand up the network** — a libp2p host with discovery (Kademlia DHT on `/revika`, DHT-only)
   and the shard/probe protocols (`internal/net`); wire node connections into a
   `store.Store` (`DHTStore`/`PlacementStore`).
3. **Construct one `provider.Manifest` per mounted domain** — `provider.New(ctx, store, signer,
   rootStore, WithConfig(cfg))`.
4. **Attach a surface** — either the sync engine (§6.2) or a mount binding (§5), or both.
5. **Run maintenance** — periodic repair (`internal/repair`, ciphertext-only) and root-pointer
   republish.
6. **Shut down cleanly** — flush in-flight mutations, persist the identity map (§6.4), close the
   host.

Suggested flags (mirror `revika-node` conventions): `-data`, `-mount <path>`, `-sync <path>`,
`-bootstrap`, `-dht`, `-signkey`, `-key`, `-repair-interval`, `-metrics`, `-v`.

### 6.2 Sync engine (`internal/sync`, planned)

OneDrive-style folder mirror (Architecture §3.7), built entirely on the `Provider` API + a
local watcher (`fsnotify`):

- **local → remote:** on a create/write/rename/delete under the watched folder, capture
  attributes with `fsmeta.Capture` and call the matching `Provider` mutation.
- **remote → local:** periodically `EnumerateChanges(sinceAnchor)`; for each delta, materialize
  into the folder (`fsmeta.Restore` / `RestoreSymlink`; `FetchContents` for content), then store
  the returned `ChangeSet.Anchor` as the new cursor.
- **conflicts:** resolve by sequence number with a **conflict-copy fallback** — never silently
  lose data. The `RootStore` anti-rollback rule makes a stale write observable; on rejection,
  refetch the current anchor, re-diff, and if a true divergence exists, write the local version
  as a conflict copy (`name (conflicted copy <seq>).ext`).

The CLI already ships a stepping-stone of this two-phase model over the namespace
(`revika-ctl ls`/`cp`, Architecture §3.8): `ls rvk:<path>` fetches **only directory blobs**
(the `readdir`/`stat` half), and `cp rvk:<path> <local>` then pulls content for just the
chosen file or subtree (the `open`/`read` fetch), driven explicitly instead of by a page fault.

### 6.3 Concurrency & consistency

- The `Provider` is safe for concurrent callers; `Manifest` serializes mutations and snapshots
  reads. A binding may call from many OS threads.
- Every mutation publishes a **new signed root** (monotonic `Seq`); a reader can therefore never
  be served a rolled-back root. Treat a `RootStore.Save` rejection as a lost race, not an error:
  reload, re-apply, retry.
- Prefer **coarse mutations**: buffer a file's writes and issue one `ModifyItem` on flush/close
  rather than per-write grafts (each graft rewrites the manifest + directory chain to a new
  root). Content-defined chunking (§3.3) keeps an edit to the affected chunk(s).

### 6.4 State the daemon must persist

| State | Why | Where (suggested) |
|---|---|---|
| Signed root pointer | the mutable anchor; anti-rollback | `RootStore` (disk `0600`, later DHT) |
| Identity map (path⇄`ItemID`) | IDs must survive daemon restarts (§3.1) | `.revika/` sidecar, `0600` |
| Last sync anchor per surface | resume `EnumerateChanges` without a full walk | `.revika/` sidecar |
| Placeholder/hydration cache (mount) | serve reads; honour `Evict` | OS cache dir |
| Keys | signing identity + share key | `.revika/keys/`, as today |

All read-capability material (root pointer, identity map if it embeds caps, sync index) carries
decryption keys and must be written as secret as a manifest (`0600`).

### 6.5 Security notes

- The daemon is **User-side and trusted**; it holds the keys. Nodes remain dumb/untrusted — no
  binding or daemon change relaxes that (Architecture §2). All chunking, encryption, and erasure
  coding happen here before any shard moves.
- The root pointer's Ed25519 signature binds `Owner || Seq || Time || rootCap`; `New` refuses a
  pointer whose `Owner` is not the daemon's signing key, and `RootStore` refuses a non-advancing
  `Seq` (D3-MAN / AU-10 / SC-8 in security/frameworks.md, per `manifest/root.go`).
- Native bindings run inside OS extension sandboxes (File Provider extension, Cloud Filter
  process). Keep secrets in the daemon process and expose only the `Provider` surface to the
  shim over a local IPC channel if the extension cannot host the Go core directly.

---

## 7. Testing guidelines

- **Core (done):** `internal/provider/provider_test.go` round-trips the full surface against an
  in-memory store + `MemRootStore` (create/enumerate/fetch, version bumps, rename-stable IDs,
  delete/ID-retire, change deltas, symlinks, persistence across reopen). Extend here first for
  any new method or semantic.
- **Sync engine:** table-driven reconcile tests — local-only, remote-only, and conflicting
  edits — asserting conflict copies are produced and never silently overwritten.
- **FUSE PoC:** mount against a `MemStore`-backed `Manifest` in a temp dir; exercise real
  `open`/`read`/`write`/`rename`/`readdir` via the OS and assert bytes + attributes round-trip
  (gate behind an env var / build tag; skip where FUSE is unavailable, as the symlink tests do).
- **Bindings:** validate each native shim against the FUSE PoC's behaviour as the oracle; assert
  the type/error mappings in §5.
- Run with `-race`; keep everything cgo-free except the native binding shims themselves.

---

## 8. Build order (walk before run)

1. **DHT-backed (or disk-backed) `RootStore`** — makes the namespace persistent/networked; the
   only missing core dependency (§4).
2. **`internal/mount` FUSE PoC** — proves the `Provider` drives a real filesystem end-to-end and
   becomes the oracle for the native bindings (§5.1).
3. **`internal/sync` + `cmd/revika-daemon`** — the folder-mirror surface and the long-lived host
   that owns everything (§6.1–§6.2). Persist the identity map and anchors (§6.4).
4. **Native bindings**, per OS, thin translation only (§5.2–§5.4) — the not-pure-Go step, a
   maintainer decision on the Swift/C#/C toolchains.

Defer, as elsewhere in revika: payment/incentive layers, global consensus, and Byzantine
reputation (Architecture §5).

---

*Keep this document in sync with `internal/provider`, `internal/fsmeta`, and Architecture.md
§3.7/§3.8 as the daemon lands.*
