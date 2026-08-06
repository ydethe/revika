# provider

revika's **OS filesystem-integration API**: the framework-neutral surface a
native "cloud provider" extension drives to present revika as an on-demand
filesystem ([Architecture §3.8](../../Architecture.md)). It is the *union* of the
operations the three native frameworks require, expressed once in Go so a single
core serves all of them:

- **macOS** — FileProvider.framework (`NSFileProviderReplicatedExtension`)
- **Windows** — Cloud Filter API (`cldapi.dll` / Sync Root, "Files On-Demand")
- **Linux** — GVfs / GIO (and FUSE via `internal/mount` as the cross-platform PoC)

Each framework speaks a different dialect, but the shape is identical: a stable
item identity, a content/metadata version pair, container enumeration with a
delta cursor, on-demand content fetch (hydration) and eviction (dehydration), and
create / modify / delete / rename mutations. `Provider` is that shape.

Nothing here touches an OS API, so the package builds and tests on every
platform. A per-OS **binding layer** (not pure Go — a cgo/Swift/C# shim, deferred
per §3.8) translates the native callbacks into these method calls.

## Mapping to the native callbacks

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
| `Rename`           | `modifyItem` (parent/filename)| rename sync                     | `move`/`set_name`|

## What backs it: `Manifest`

The default `Provider`, `Manifest`, resolves every call against revika's
cap-addressed Merkle DAG ([`internal/manifest`](../manifest/README.md)) over any
`store.Store`:

- **reads** (`Stat`/`Lookup`/`Enumerate`) load directory and manifest blobs —
  enumeration touches no file content, so a listing is cheap;
- **fetch** runs [`pipeline.LoadFile`](../pipeline/README.md) to hydrate bytes on
  demand;
- **mutations** (`CreateItem`/`ModifyItem`/`DeleteItem`/`Rename`) are each a
  copy-on-write `manifest.Graft`/`GraftRemove` that advances a signed
  `RootPointer` (§4). A rename re-grafts the *same* content-addressed child cap at
  the destination, so the moved item keeps its shards and versions untouched.

Nodes still see only content-addressed ciphertext shards; all naming, tree shape,
versioning, and identity live here on the User side.

### The mutable-anchor seam: `RootStore`

Advancing the namespace means publishing a new signed `RootPointer`. Persisting /
publishing that pointer is isolated behind the `RootStore` interface, which now has
both a durable local implementation **and** a networked one:

- **`MemRootStore`** — in-memory, for tests and a single-process mount.
- **`FileRootStore`** (`file_rootstore.go`) — persists the signed pointer to a
  local JSON file (default `.revika/root.json`), the durable anchor `revika-ctl`
  reads and advances between invocations. It writes `0600` under a `0700` dir
  (SC-28: the file names the root cap, which unlocks the whole namespace) and
  enforces the same anti-rollback `Seq` and owner-match checks (SC-8) a networked
  store will. Its `EncodeRootPointer`/`DecodeRootPointer` codec is reused to build
  a **sealed shared root**: a `RootPointer` anchored at a shared subtree, wrapped
  to a recipient with ML-KEM-768 so only they can open it (`revika-ctl share`).
- **`DHTRootStore`** (`rootstore.go`) — publishes/resolves the pointer over the DHT
  (§4/§6), scoped to one owner. It rides on a local `RootPublisher` interface
  (`PutRoot`/`GetRoot`), satisfied structurally by `*net.Discovery`, so `provider`
  never imports `net` (the interface breaks the cycle). `PutRoot` strips the cap to
  its **verify projection** before publishing, so a mirror never leaks a decryption
  key to the public DHT; `Save` pre-checks owner-match + `Seq`-advance before it
  hits the network.
- **`MultiRootStore`** (`rootstore.go`) — composes a durable **primary** with
  best-effort **mirrors**: `Load` reads the authoritative primary only; `Save`
  commits the primary first and, only on success, fans out to the mirrors, logging
  and swallowing a mirror failure so a DHT-publish outage can never fail a local
  commit. This is the `revika-ctl` combination — `FileRootStore` primary +
  `DHTRootStore` mirror.

## Item identity

The frameworks require an identifier that is **stable across renames and moves**
(File Provider `itemIdentifier`, Cloud Filter `FileIdentity`). revika's content
caps are not that — a file's cap is stable across rename but changes on every
edit — so identity is owned here (`identity.go`): the provider is the sole mutator
of its domain, so it maintains an authoritative path⇄`ItemID` map and re-keys it
on `Rename`/`Delete`. A future manifest `Entry.ID` field (§3.6) could make
identity intrinsic to the DAG; until then this index is authoritative.

## Change enumeration

`EnumerateChanges` diffs the anchor's root cap against the current one over the
Merkle DAG (`diff.go`). Because two equal caps address an identical subtree, **cap
equality prunes whole unchanged branches** without reading them — the diff cost is
proportional to what actually changed, not to the size of the namespace. It
returns added / modified / deleted deltas plus a fresh `SyncAnchor`, mapping to
File Provider's `enumerateChanges(from:)` and a Cloud Filter USN sweep.

## Versions

`ItemVersion{Content, Meta}` is the change-token pair every framework uses to tell
"same content, new name" from "new content" without downloading a shard (File
Provider `NSFileProviderItemVersion`, Cloud Filter drift detection). For files the
tokens come from [`pipeline.DeriveVersions`](../pipeline/README.md); for
directories they are derived from the blob cap (which commits to the subtree).

## Status

- ✅ Full `Provider` surface over the manifest DAG + `MemRootStore`, round-trip
  tested (`provider_test.go`).
- ✅ `FileRootStore` — durable local `RootPointer`, backing `revika-ctl`'s
  namespace commands and sealed shared roots (`file_rootstore_test.go`).
- ✅ `DHTRootStore` + `MultiRootStore` (§4/§6) — publishing the pointer network-wide
  (behind the durable local file) so a namespace is multi-device and a published
  root is resolvable by owner pubkey (`dht_rootstore_test.go`; the wire side lives in
  [`internal/net`](../net/README.md)).
- ⏳ Per-OS binding layer (`internal/mount` FUSE PoC first, then the native
  shims — a cgo/Swift/C# decision for the maintainer, §3.8).
