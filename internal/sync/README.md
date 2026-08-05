# sync

revika's **folder-watch + reconcile engine**: it keeps a local directory and a
User's stored namespace in agreement, **both ways**
([Architecture §3.7/§3.8](../../Architecture.md); the "daemon folder-watch +
reconcile" of [CLAUDE.md](../../CLAUDE.md)'s repo layout).

Where [`internal/provider`](../provider/README.md) is the on-demand, per-callback
filesystem surface a *native OS extension* drives, this package is the
standalone, headless alternative: a background loop that periodically scans a
real directory, diffs it against the stored tree, and applies the deltas in both
directions — the model a `revika-daemon` runs to turn an ordinary folder into a
synced folder with no OS integration.

Everything flows through `provider.Provider`, so every uploaded byte is chunked,
encrypted, and erasure-coded **client-side** before any shard leaves the machine
— the engine never weakens revika's guarantee.

## Three-way reconcile

Two-way sync can't tell "I changed this" from "they deleted it". A *three-way*
reconcile can: the engine persists a **base** — the last point the two sides
agreed — and compares the current local scan and remote scan against it.

| local vs base | remote vs base | action |
|---|---|---|
| new / changed | unchanged | **upload** (create/modify remote) |
| unchanged | new / changed | **download** (create/modify local) |
| deleted | unchanged | **delete remote** |
| unchanged | deleted | **delete local** |
| changed | changed | **conflict** → `ConflictPolicy` |
| new | new (no base) | **conflict** → `ConflictPolicy` |

Because the stored tree is a Merkle DAG of content-addressed blobs, the remote
side exposes cheap content/metadata version tokens (`provider.ItemVersion`), so
"changed remotely" is a **token comparison, never a re-download**. Local change
detection uses size + mtime (the classic rsync heuristic).

### Conflicts

`ConflictPolicy` decides a both-changed path:

- **`PreferLocal`** *(default)* — the local working copy wins (upload; a local
  delete propagates as a remote delete).
- **`PreferRemote`** — the stored namespace wins (download; a remote delete
  propagates locally).
- **`Skip`** — leave both sides untouched, report the conflict, and **preserve
  the base** so it resurfaces next pass until a human resolves it.

## Watching without a kernel hook

The PoC watches by **polling** (`Daemon`), not a kernel notification API: it
re-scans on a fixed cadence. This keeps the package pure-Go and dependency-free,
portable across every OS, and trivially testable (a test just calls `Reconcile`).
Wiring an event source (inotify / FSEvents / ReadDirectoryChanges, or the native
provider callbacks) to *trigger* a reconcile sooner is a drop-in refinement — the
reconcile logic is identical either way.

## API

```go
r, _ := sync.New(localDir, prov,
    sync.WithConflictPolicy(sync.PreferLocal),
    sync.WithLogger(log.Printf),
    sync.WithIgnore(func(rel string) bool { return strings.HasSuffix(rel, ".tmp") }),
)

res, err := r.Reconcile(ctx)      // one full pass, both directions
plan, err := r.PlanOnly(ctx)      // dry run: the deltas without applying them

d := sync.NewDaemon(r, 30*time.Second,
    sync.WithOnResult(func(r sync.Result) { /* log */ }),
    sync.WithOnError(func(err error) { /* log */ }),
)
d.Run(ctx)                        // reconcile now, then every interval, until ctx is cancelled
```

`Reconcile` returns a `Result` (counts of uploads/downloads/deletes/conflicts and
a slice of per-operation errors). A single bad path is collected in
`Result.Errors` rather than aborting the pass, so a partial reconcile still makes
progress; only a failure to *scan* or to *persist the base* returns an error.

## State sidecar

The base is stored at `<root>/.revika-sync-state.json` (override with
`WithStatePath`). It is local bookkeeping — like `.git`, excluded from the synced
tree — and holds only sizes, mtimes, and opaque version tokens (no decryption
keys), written `0600` and updated atomically (write-temp-then-rename) so a crash
mid-write never leaves a half-written base.

## Operation ordering

A plan is applied **creations parents-first, deletions children-first**: a
child's parent directory always exists before the child is created, and a subtree
is torn down leaves-up. Missing remote directories are created lazily as files
are uploaded into them; empty directories sync as explicit `mkdir` operations.

## Not yet

- **Content-hash change detection** — size+mtime can miss a same-size,
  same-mtime edit; a hashing pass is the follow-up.
- **Rename detection** — a move surfaces as delete + add (correct, but re-uploads
  the bytes instead of a cheap copy-on-write graft).
- **Directory-vs-file swap** at one path is treated as a conflict (never silently
  clobbered).
- **Partial-file transfer** — a changed file is re-uploaded whole.

## Testing

`go test ./internal/sync` (add `-race`). Unit tests cover every reconcile
direction, all three conflict policies, symlinks, the no-op-when-in-sync
invariant, state-sidecar exclusion, and plan ordering. `e2e_test.go` drives two
independent local mirrors of one stored namespace through a full lifecycle
(seed → edit both ways → delete both ways → rename), a multi-chunk erasure
round-trip, and the polling `Daemon` — all through the real manifest Provider.
