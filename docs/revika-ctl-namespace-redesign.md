# revika-ctl namespace CLI redesign

Status: **implemented** — the command surface below (`keygen`/`cp`/`ls`/`rm`/`share`/`node`),
the `provider.FileRootStore` persistence seam, and the sealed-shared-root model are all in
`cmd/revika-ctl` + `internal/provider`, covered by unit tests, `TestNamespaceE2E`
(`cmd/revika-ctl/namespace_e2e_test.go`), and the `deploy/*.sh` compose scenarios. This doc is
retained as the design rationale; sections written in the future tense describe the pre-change
state they replaced.
Author: design draft
Scope: `cmd/revika-ctl` command surface + one new persistence seam. No changes to
crypto, erasure, networking, or the `internal/manifest` DAG primitives.

## 1. Motivation

Today revika-ctl is **manifest-file-centric**. `put` writes a `report.pdf.rvk.json`
read-capability that the user must keep, track, and hand to `get`/`share`. There is no
notion of "where a file lives" — every file is an island addressed by a local sidecar.

The target model is **namespace-centric**, exactly what `internal/manifest` was built for
but never wired into the CLI: one persistent, mutable **root directory per user**, into
which files are placed by name and addressed with `rvk:` paths.

```
# store into the namespace
cp report.pdf rvk:docs/reports/

# retrieve from the namespace
cp rvk:docs/reports/report.pdf ./local/

# browse the namespace
ls rvk:docs
```

This turns revika-ctl into something that reads like coreutils over a private, encrypted,
distributed filesystem — `cp`, `ls`, `rm` — instead of a manifest-shuffling tool.

## 2. What already exists (reused, not rebuilt)

All the mutable-namespace machinery is present in `internal/manifest` and `internal/provider`:

| Primitive | Role |
|-----------|------|
| `manifest.RootPointer` (`root.go`) | The one signed, mutable anchor: owner Ed25519 key → current root cap, monotonic `Seq`, timestamp. `SignRoot` / `Verify`. |
| `manifest.Resolve(root, "a/b/c")` (`dir.go`) | Walk a slash path from a root cap to a child cap. |
| `manifest.Graft(root, "a/b/c", child, stat)` | COW-insert a cap, returns a new root cap; creates missing intermediate dirs. |
| `manifest.GraftRemove(root, "a/b/c")` | COW-delete an entry, returns a new root cap. |
| `manifest.LoadDir` / `StoreDir` / `NewDir` | Read/write a `DirManifest` (KindDir blob). |
| `manifest.StoreFileManifest` / `LoadFileManifest` | Wrap a `pipeline.FileManifest` as a KindFile blob and back. |
| `manifest.WrapCap(recipient, cap)` | Seal a cap to a recipient pubkey (used by `share`). |
| `provider.RootStore` (`rootstore.go`) | The load/save **seam** for the pointer. Only `MemRootStore` exists; the DHT-backed publisher is explicitly "planned". |

The existing revika-ctl helpers are also kept verbatim as internal plumbing:
`runStore`, `runLoad`, `storeTree`, `restoreTree`, `restoreFile`, `restoreDir`,
`statFromManifest`, the backend dialers (`dial`, `dialSigned`, `dialDHT`,
`dialPlacement`, `getBackend`, `putBackend`), and discovery (`discoverNodes`,
`discoverNodeInfos`).

## 3. The one genuinely new piece: a persistent, selectable root file

### 3.1 The root file *is* the tree selector

Every command that touches the namespace resolves **which tree** through one flag:

```
-root <path>          # default: $REVIKA_ROOT, else .revika/root.json
```

A root file is a `manifest.RootPointer` (JSON): `{Owner, Root ReadCap, Seq, TimeNS, Sig}`.
Its `Root` cap addresses (and, being a `ReadCap`, carries the key to) a directory subtree.
There are two kinds, distinguished purely by whose signing key `Owner` is:

- **Owned root** — `Owner == your signing pubkey`. Your live, mutable namespace
  (`.revika/root.json` by default). `cp LOCAL rvk:…` and `rm rvk:…` graft/remove and
  advance `Seq`; `ls`/`cp rvk:… LOCAL` read it.
- **Shared (foreign) root** — `Owner != you`. A snapshot someone `share`d with you,
  pointed at with `-root theirs.json`. **Read-only**: `ls` and `cp rvk:PATH LOCAL` work;
  any mutation (`cp … rvk:`, `rm`) is rejected with "read-only shared root (you are not its
  owner)". Because it is a full `RootPointer`, its signature proves provenance — you can
  see who shared it.

This unifies "browse my tree" and "browse a tree shared with me" into one mechanism:
default `-root` for mine, `-root shared.json` for theirs.

### 3.2 Shared roots are sealed to the recipient

To honor the settled Architecture constraint — *"Sharing = wrapping keys … a
read-capability wrapped with the recipient's public key"* — a shared root file is **sealed
with `manifest.WrapCap(recipient, rootPointerBytes)`**, not left as a plaintext bearer cap.
The recipient supplies their ML-KEM private key to open it:

```
ls  -root shared.json -key ~/.revika/keys/user.key rvk:
cp  -root shared.json -key ~/.revika/keys/user.key rvk:reports/q3.pdf ./
```

Resolving a root file therefore: read bytes → if they parse as a plaintext `RootPointer`,
use it (an owned root, or an explicitly-unsealed one); otherwise treat as sealed and
`cap.Unwrap` with `-key` → `RootPointer`. Then `Verify()` the signature. (Whether to also
allow an *unsealed* plaintext bearer root is the one open crypto question — see §9.)

### 3.3 Persistence seam: `FileRootStore`

```
// internal/provider/rootstore.go (or a new file_rootstore.go)
type FileRootStore struct {
    path   string        // -root / $REVIKA_ROOT / .revika/root.json
    signer cap.SignKey   // owner identity; needed to advance the pointer
}
func NewFileRootStore(path string, signer cap.SignKey) *FileRootStore
func (f *FileRootStore) Load(ctx) (RootPointer, ok bool, err error)   // read + Verify the JSON
func (f *FileRootStore) Save(ctx, rp RootPointer) error               // reject non-advancing Seq, write 0600
```

- Mode `0600` (the file names the root cap, which unlocks the whole namespace — as secret
  as any manifest).
- `Save` enforces the same anti-rollback rule as `MemRootStore` (reject `Seq <= stored`)
  and is only ever called for an **owned** root.
- When the DHT root-publish lands (Architecture §4/§6) it slots into the *same* `RootStore`
  interface — **no CLI change**. Until then a root is visible only where its file is. This
  is the single stated limitation of the design, called out in `--help` and CLAUDE.md.

Two helpers wrap the common flows:

```
// resolveRoot returns the tree named by -root: its root cap, Seq, and whether it is
// writable (owned by our signer). A sealed foreign root is unwrapped with -key.
func resolveRoot(path string, signer cap.SignKey, key *cap.PrivateKey) (root manifest.ReadCap, seq uint64, writable bool, err error)

// commitRoot re-signs newRoot at Seq+1 and Saves it (owned/writable roots only).
func commitRoot(ctx, rs *FileRootStore, newRoot manifest.ReadCap, prevSeq uint64) error
```

Bootstrap detail: the first-ever write to an owned root that does not exist yet does
`StoreDir(NewDir(empty))` → `SignRoot(seq=1)` → `Save`, then grafts onto it.

## 4. `rvk:` addressing

A one-function parser, `parseEndpoint(arg string)`:

- Prefix `rvk:` → a **namespace endpoint**; the remainder is a clean slash path
  (`rvk:` alone = the root itself, `rvk:docs/a.pdf` = path `docs/a.pdf`). Reuses
  `manifest.splitPath` semantics (rejects `..`). The tree it addresses is whichever
  `-root` file is in effect (owned by default, or a shared root — §3).
- Anything else → a **local filesystem path**.

There is no separate `.cap` source form: reading something shared with you is just
`ls`/`cp` with `-root theirs.json` (§3), so `rvk:` paths and shares are one mechanism.

`cp` infers direction from which side carries `rvk:` (scp-style). Trailing-slash /
existing-dir rules follow `cp`: `cp a.pdf rvk:docs/` → `docs/a.pdf`;
`cp a.pdf rvk:docs/b.pdf` → store under name `b.pdf`.

## 5. Command surface

Every namespace command takes `-root <path>` (default `$REVIKA_ROOT`, else
`.revika/root.json`) and, for a sealed shared root, `-key <path>`.

| New command | Replaces | One-line behavior |
|-------------|----------|-------------------|
| `cp LOCAL rvk:PATH` | `put` | Store file/dir; graft its cap into the `-root` tree at `PATH`; advance `Seq`. Owned root only. |
| `cp rvk:PATH LOCAL` | `get` + `hydrate` | Resolve `PATH` in the `-root` tree; restore file or subtree to `LOCAL`. |
| `ls [rvk:PATH]` | `sync` (browse) | Resolve `PATH` in the `-root` tree, `LoadDir`, print entries. `ls` / `ls rvk:` = root. |
| `rm rvk:PATH` | `delete` | `GraftRemove` from the `-root` tree + drop shard ownership. Owned root only. |
| `node` | `nodes` | Unchanged behavior, singular name. |
| `keygen` | `keygen` | Unchanged. |
| `share rvk:PATH -to K -o shared.json` | `share -manifest` | Resolve `PATH` → build a `RootPointer` at that subtree → seal to `K` → write a shared root file. |

Reading a tree shared with you is not a distinct command — it is any read command with
`-root shared.json -key <your-priv>` (§3.1). Mutating commands (`cp … rvk:`, `rm`) refuse a
foreign root.

**Removed entirely:** the `put`, `get`, `sync`, `hydrate`, `nodes` command names; the
lazy placeholder/stub model (`.revika-sync.json`, `sync.go`'s `syncTree`/`writePlaceholder`
/`cmdHydrate`/`planHydrate` and friends); the user-facing `.rvk.json` manifest artifact;
the separate `.cap` share artifact; the `-manifest` / `-cap` / `-r` flags.

### 5.1 `cp` in detail

Flags: `-root <path>`, `-key <path>` (open a sealed shared root),
`-node <ma> | -bootstrap <ma>… | -mdns` (backend), `-signkey <path>` (writes to an owned
root), `-grant-ttl` (repair-grant expiry, as today's `put`). `-r` is gone — direction and
file-vs-dir are inferred (`rvk:` Kind is authoritative; a local source's dir-ness comes
from `Lstat`).

- **Store** (`cp LOCAL rvk:PATH`) — requires a writable (owned) `-root`:
  1. `resolveRoot` → root cap + `writable` (error if foreign) + `seq`.
  2. Local file → `runStore` + `manifest.StoreFileManifest` → file cap.
     Local dir → `storeTree` → subtree root cap.
  3. `manifest.Graft(root, PATH, cap, stat)` (dir uses `StatCache{Kind:KindDir}`;
     file uses `statFromManifest`).
  4. `commitRoot` (sign `Seq+1`, save).
- **Retrieve** (`cp rvk:PATH LOCAL`) — owned or shared `-root`:
  1. `resolveRoot` (unseal with `-key` if foreign); `manifest.Resolve(root, PATH)` → cap.
  2. `KindFile` → `restoreFile`; `KindDir` → `restoreTree`.

### 5.2 `ls` in detail

Flags: `-root`, `-key`, backend selection, `-l` (long), `-R` (recursive). Reads entries
straight from the parent directory's `StatCache`, so **no file content is fetched** (the
browse half of the old `sync`, without writing anything to disk).

- Default output: one entry name per line (coreutils-style), dirs suffixed `/`.
- `-l`: kind (`dir`/`file`/`link`), size, mtime, name — columns from `StatCache`.
- `-R`: recurse (each subdirectory is another `LoadDir`).
- `ls` / `ls rvk:` lists the `-root` tree's top level; a `KindFile` root lists just that
  single file.

### 5.3 Store wiring note (implementation risk to resolve first)

`cp rvk:…` (store) and `rm` **read** directory blobs on the path (`Graft`/`GraftRemove`
call `LoadDir`) **and write** new ones. The backing `store.Store` must therefore support
both `Get` and `Put`/`Delete`:

- Single `-node`: `NetStore` already does Get+Put+Delete — trivial, and the recommended
  first target for the PoC.
- DHT multi-node: writes go through `PlacementStore` but reads need `DHTStore`
  (provider discovery). Needs a small combined store (write via placement, read via DHT)
  or resolving the root DAG through a `DHTStore` while grafting new blobs through the
  placement store. Flag this as the first thing to prototype; single-node `cp`/`ls`/`rm`
  can land before it.

## 6. `share` produces a shared root file

`share` no longer emits a bare `.cap`; it produces a **shared root file** — the same
artifact `-root` consumes (§3) — so sharing and browsing use one file type.

`share rvk:docs/report.pdf -to <pubkey|@file> -o shared-report.json`:
1. Backend + `resolveRoot` (your `-root`) + `manifest.Resolve(root, "docs/report.pdf")`
   → child cap (a `KindFile` here, or a `KindDir` when sharing a subtree).
2. `manifest.SignRoot(yourSignKey, child, seq=1, timeNS)` → a `RootPointer` anchored at the
   shared subtree, signed by you (provenance).
3. `manifest.WrapCap(recipient, rootPointerBytes)` → sealed `shared-report.json`.
4. Recipient uses it as any other root:
   `ls -root shared-report.json -key <their-priv>` /
   `cp -root shared-report.json -key <their-priv> rvk: ./out`.

The shared file grants read of that subtree and nothing outside it (the cap commits only to
that subDAG). It is a static snapshot — it does not track later changes to your tree; re-run
`share` to hand out a newer one. Because it is signed but **not** your `.revika/root.json`,
the recipient's tools treat it read-only (`Owner != them`, and it is not their owned root).

## 7. File-by-file change plan

- `internal/provider/rootstore.go` (or new `file_rootstore.go`) — add `FileRootStore`
  (+ README note). Unit test round-trips load/save and rejects a stale Seq.
- `cmd/revika-ctl/main.go` — rewrite `switch cmd`: `cp`, `ls`, `rm`, `node`, `keygen`,
  `share`, `help`. Delete `put`/`get`/`sync`/`hydrate`/`nodes` cases. Rewrite `usage()`.
- `cmd/revika-ctl/commands.go` — replace `cmdPut`/`cmdGet`/`cmdDelete`/`cmdNodes` with
  `cmdCp`/`cmdLs`/`cmdRm`/`cmdNode`; keep `cmdKeygen`; rewrite `cmdShare` to resolve `rvk:`
  and emit a sealed shared root. Add `parseEndpoint`, `resolveRoot`, `commitRoot`, and the
  `-root`/`REVIKA_ROOT` resolution. Keep every dialer/discovery helper.
- `cmd/revika-ctl/tree.go` — keep `storeTree`/`restoreTree`/`restoreFile`/`restoreDir`/
  `statFromManifest`; drop `putTree`/`getTree`/`writeRootCap` (their command wrappers go).
- `cmd/revika-ctl/sync.go` — **delete** (placeholder/stub model dropped). Remove
  `sync_test.go` cases, keep any still-relevant helpers if shared (none are).
- `cmd/revika-ctl/manifest.go` — prune to what `cp`/`share` still use; the user-facing
  `.rvk.json` encode path goes.
- Tests: `ctl_test.go`, `meta_test.go`, `tree_test.go`, `sync_test.go` — rewrite around
  the new verbs; add an end-to-end `cp→ls→cp→rm→ls` round-trip against a mem/single-node
  store, and a `share rvk:… → ls/cp -root shared.json -key …` round-trip (incl. asserting a
  foreign root refuses `cp … rvk:`/`rm`).
- Docs: this file; `cmd/revika-ctl` has no README today — add one, or fold usage into
  `--help`. Update **CLAUDE.md** (Commands block + repo-layout line for revika-ctl) and
  **Architecture.md** (§4 RootPointer is now realized in the CLI via `FileRootStore`;
  §3.8 note that CLI dropped the placeholder model, which stays a Provider/mount concern).

## 8. What is explicitly deferred / out of scope

- **DHT root publish** — the namespace stays single-machine until the planned DHT-backed
  `RootStore` lands. `FileRootStore` is the drop-in seam; no CLI change when it arrives.
- **Multi-device conflict reconciliation** — handled by the `sync/` layer, not this CLI.
- **The lazy "online-only" placeholder model** — dropped from the CLI per this design, but
  it remains a legitimate concern of the native mount `provider/` (Architecture §3.8);
  removing it from revika-ctl does not remove it from the system.
- `rm` on the namespace drops ownership like today's `delete`; garbage collection of the
  now-unreferenced blobs is the node's job (lease/GC), unchanged.

## 9. Resolved decisions & remaining open questions

**Resolved (this revision):**
- Root file is overridable: `-root <path>`, else `$REVIKA_ROOT`, else `.revika/root.json`.
- `ls` is plain (name-per-line) by default, `-l` for detail, `-R` recursive — coreutils-style.
- `share` emits a **shared root file** (a sealed `RootPointer`), consumed via `-root`; the
  separate `.cap` artifact is dropped. Sharing and tree-selection are one mechanism.

**Resolved:**
- **Sealed only, no bearer.** A shared root is always sealed to the recipient's ML-KEM
  public key (`manifest.WrapCap` / `cap.Wrap`); the recipient passes `-key` to open it. The
  settled *"sharing = wrapped with the recipient's public key"* constraint stands — there is
  no plaintext bearer root.

**Still open:**
1. **Combined read+write store for DHT `cp`/`rm`** (§5.3) — prototype now, or ship
   single-node first and follow up?
2. **Owned-root Seq durability.** With only a local `.revika/root.json`, `Seq` advances
   locally; two machines editing the same owned namespace will diverge until DHT publish +
   the `sync/` reconcile land. Acceptable for the PoC? (Assumed yes.)
