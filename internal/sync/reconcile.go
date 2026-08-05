package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	stdsync "sync"

	"revika/internal/fsmeta"
	"revika/internal/pipeline"
	"revika/internal/provider"
)

// ConflictPolicy decides what happens when both sides changed a path since they
// last agreed (or both created it independently, with no base to arbitrate).
type ConflictPolicy int

const (
	// PreferLocal resolves conflicts in favour of the local working copy: the
	// local version is uploaded over the remote, and a local deletion wins over a
	// remote change (the remote item is deleted). This is the default — for a
	// "sync my folder up" tool the local copy is what the user is editing.
	PreferLocal ConflictPolicy = iota
	// PreferRemote resolves conflicts in favour of the stored namespace: the
	// remote version is downloaded over the local, and a remote deletion wins.
	PreferRemote
	// Skip leaves a conflicted path untouched on both sides and reports it, so a
	// human (or a higher layer) resolves it. The base is preserved, so the
	// conflict resurfaces on the next reconcile until resolved.
	Skip
)

// OpKind is the type of a reconcile operation.
type OpKind int

const (
	OpMkdirRemote  OpKind = iota // create a directory in the stored tree
	OpMkdirLocal                 // create a directory on disk
	OpUpload                     // create or replace a remote file/symlink from local
	OpDownload                   // create or replace a local file/symlink from remote
	OpDeleteRemote               // remove an item (and subtree) from the stored tree
	OpDeleteLocal                // remove a file/directory from disk
	OpConflict                   // a conflict left unresolved (ConflictPolicy Skip)
)

// String renders an OpKind for logs.
func (k OpKind) String() string {
	switch k {
	case OpMkdirRemote:
		return "mkdir-remote"
	case OpMkdirLocal:
		return "mkdir-local"
	case OpUpload:
		return "upload"
	case OpDownload:
		return "download"
	case OpDeleteRemote:
		return "delete-remote"
	case OpDeleteLocal:
		return "delete-local"
	case OpConflict:
		return "conflict"
	default:
		return fmt.Sprintf("op(%d)", int(k))
	}
}

// Op is one reconcile action on a path. Reason is a short human-readable note
// (e.g. "local changed", "both changed → prefer-local") for logging.
type Op struct {
	Kind      OpKind
	Path      string // slash-relative to the sync root
	IsDir     bool
	IsSymlink bool
	Reason    string
}

// Plan is the ordered set of operations one reconcile pass will apply. Ops are
// pre-sorted for safe application: creations parents-first, deletions
// children-first (see Reconciler.Plan).
type Plan struct {
	Ops []Op
	// skipped records paths whose conflict was left unresolved, so Apply can
	// preserve their base entry rather than recording a false agreement.
	skipped map[string]bool
}

// Empty reports whether the plan has no operations.
func (p Plan) Empty() bool { return len(p.Ops) == 0 }

// Result summarizes what a reconcile applied (or would apply, from a Plan).
type Result struct {
	Uploaded      int
	Downloaded    int
	DeletedRemote int
	DeletedLocal  int
	MkdirRemote   int
	MkdirLocal    int
	Conflicts     int
	// Errors holds per-operation failures; a single bad path does not abort the
	// pass, so a partial reconcile still makes progress.
	Errors []error
}

// Reconciler keeps a local directory (Root) and a provider.Provider namespace in
// two-way agreement. It is safe to reuse across passes but not to run two passes
// concurrently on the same Reconciler (they share the base sidecar); a mutex
// enforces that.
type Reconciler struct {
	root      string
	prov      provider.Provider
	statePath string
	conflict  ConflictPolicy
	cfg       pipeline.Config
	ignore    func(rel string) bool
	logf      func(format string, args ...any)

	mu stdsync.Mutex
}

// Option configures a Reconciler.
type Option func(*Reconciler)

// WithConflictPolicy sets how conflicts are resolved (default PreferLocal).
func WithConflictPolicy(p ConflictPolicy) Option { return func(r *Reconciler) { r.conflict = p } }

// WithStatePath overrides where the base sidecar is stored (default
// <root>/.revika-sync-state.json).
func WithStatePath(path string) Option { return func(r *Reconciler) { r.statePath = path } }

// WithLogger sets a log sink for per-operation progress (default: no logging).
func WithLogger(logf func(format string, args ...any)) Option {
	return func(r *Reconciler) { r.logf = logf }
}

// WithIgnore adds a predicate that excludes matching slash-relative paths from
// the local scan (the state sidecar is always excluded). A directory that is
// ignored is not descended into.
func WithIgnore(pred func(rel string) bool) Option {
	return func(r *Reconciler) {
		base := r.ignore
		r.ignore = func(rel string) bool { return base(rel) || pred(rel) }
	}
}

// New returns a Reconciler syncing the local directory root against prov. The
// directory is created if absent.
func New(root string, prov provider.Provider, opts ...Option) (*Reconciler, error) {
	if root == "" {
		return nil, errors.New("sync: root directory is required")
	}
	if prov == nil {
		return nil, errors.New("sync: provider is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("sync: resolve root: %w", err)
	}
	r := &Reconciler{
		root:      abs,
		prov:      prov,
		statePath: filepath.Join(abs, StateFileName),
		conflict:  PreferLocal,
		cfg:       pipeline.DefaultConfig(),
		logf:      func(string, ...any) {},
	}
	// The state sidecar is never part of the synced tree.
	r.ignore = func(rel string) bool { return rel == StateFileName }
	for _, o := range opts {
		o(r)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("sync: create root %q: %w", abs, err)
	}
	return r, nil
}

// Reconcile runs one full pass: scan both sides, plan the deltas, apply them,
// and persist the new agreement. It returns what it did. A per-operation failure
// is collected in Result.Errors rather than aborting the pass; only a failure to
// scan or to persist the base returns an error.
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	base, err := loadState(r.statePath)
	if err != nil {
		return Result{}, err
	}
	local, err := scanLocal(r.root, r.ignore)
	if err != nil {
		return Result{}, err
	}
	remote, err := scanRemote(ctx, r.prov)
	if err != nil {
		return Result{}, err
	}

	plan := r.plan(base, local, remote)
	res := r.apply(ctx, plan)

	newBase, err := r.rebuildBase(ctx, base, plan.skipped)
	if err != nil {
		return res, err
	}
	if err := saveState(r.statePath, newBase); err != nil {
		return res, err
	}
	return res, nil
}

// PlanOnly computes the reconcile plan without applying it — useful for a dry
// run or for surfacing pending changes.
func (r *Reconciler) PlanOnly(ctx context.Context) (Plan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	base, err := loadState(r.statePath)
	if err != nil {
		return Plan{}, err
	}
	local, err := scanLocal(r.root, r.ignore)
	if err != nil {
		return Plan{}, err
	}
	remote, err := scanRemote(ctx, r.prov)
	if err != nil {
		return Plan{}, err
	}
	return r.plan(base, local, remote), nil
}

// plan computes the reconcile operations from the three snapshots.
func (r *Reconciler) plan(base *baseState, local localSnapshot, remote remoteSnapshot) Plan {
	// Union of every path any side knows about.
	paths := map[string]struct{}{}
	for p := range local {
		paths[p] = struct{}{}
	}
	for p := range remote {
		paths[p] = struct{}{}
	}
	for p := range base.Entries {
		paths[p] = struct{}{}
	}

	var ops []Op
	skipped := map[string]bool{}
	for p := range paths {
		ls, lok := local[p]
		rs, rok := remote[p]
		be, bok := base.Entries[p]
		op, skip := r.decide(p, ls, lok, rs, rok, be, bok)
		if skip {
			skipped[p] = true
		}
		if op != nil {
			ops = append(ops, *op)
		}
	}

	// Order for safe application: non-deletes parents-first (a child's parent
	// directory exists before the child is created), deletes children-first.
	sort.SliceStable(ops, func(i, j int) bool {
		di, dj := isDelete(ops[i].Kind), isDelete(ops[j].Kind)
		if di != dj {
			return !di // non-deletes before deletes
		}
		if di { // both deletes: deeper paths first
			return depth(ops[i].Path) > depth(ops[j].Path)
		}
		// both creations/edits: shallower paths first
		if depth(ops[i].Path) != depth(ops[j].Path) {
			return depth(ops[i].Path) < depth(ops[j].Path)
		}
		return ops[i].Path < ops[j].Path
	})
	return Plan{Ops: ops, skipped: skipped}
}

// decide turns one path's three-way state into an operation (or none). It
// returns skip=true when the path is a conflict left unresolved (ConflictPolicy
// Skip), so its base entry is preserved.
func (r *Reconciler) decide(p string, ls localState, lok bool, rs remoteState, rok bool, be baseEntry, bok bool) (*Op, bool) {
	switch {
	case lok && rok:
		return r.decideBoth(p, ls, rs, be, bok)
	case lok && !rok:
		return r.decideLocalOnly(p, ls, be, bok, rs)
	case !lok && rok:
		return r.decideRemoteOnly(p, rs, be, bok, ls)
	default:
		// Neither side has it; the base entry is stale — drop it (no op).
		return nil, false
	}
}

// decideBoth handles a path present on both sides.
func (r *Reconciler) decideBoth(p string, ls localState, rs remoteState, be baseEntry, bok bool) (*Op, bool) {
	// A directory-vs-leaf swap at one path is ambiguous and rare; treat it as a
	// conflict so we never silently clobber one representation with the other.
	if ls.kind != rs.kind {
		return r.conflictOp(p, ls, true, rs, true, "kind mismatch (dir vs file)")
	}
	if ls.kind == kindDir {
		// Both directories: structural, no content to move. Ensure the agreement
		// is recorded (adopt) but emit no operation.
		return nil, false
	}
	lChanged := !bok || !be.localMatches(ls)
	rChanged := !bok || !be.remoteMatches(rs)
	switch {
	case lChanged && rChanged:
		return r.conflictOp(p, ls, true, rs, true, "both changed")
	case lChanged:
		return &Op{Kind: OpUpload, Path: p, IsSymlink: ls.isSymlink, Reason: "local changed"}, false
	case rChanged:
		return &Op{Kind: OpDownload, Path: p, IsSymlink: rs.isSymlink, Reason: "remote changed"}, false
	default:
		return nil, false // unchanged on both sides
	}
}

// decideLocalOnly handles a path present locally but not remotely.
func (r *Reconciler) decideLocalOnly(p string, ls localState, be baseEntry, bok bool, rsAbsent remoteState) (*Op, bool) {
	if bok {
		// It was in the base, so the remote side deleted it since agreement.
		if be.localMatches(ls) {
			// Local unchanged → the remote deletion propagates.
			if ls.kind == kindDir {
				return &Op{Kind: OpDeleteLocal, Path: p, IsDir: true, Reason: "deleted remotely"}, false
			}
			return &Op{Kind: OpDeleteLocal, Path: p, Reason: "deleted remotely"}, false
		}
		// Local changed but remote deleted → conflict.
		return r.conflictOp(p, ls, true, rsAbsent, false, "changed locally, deleted remotely")
	}
	// New locally → upload (mkdir for a directory).
	if ls.kind == kindDir {
		return &Op{Kind: OpMkdirRemote, Path: p, IsDir: true, Reason: "new locally"}, false
	}
	return &Op{Kind: OpUpload, Path: p, IsSymlink: ls.isSymlink, Reason: "new locally"}, false
}

// decideRemoteOnly handles a path present remotely but not locally.
func (r *Reconciler) decideRemoteOnly(p string, rs remoteState, be baseEntry, bok bool, lsAbsent localState) (*Op, bool) {
	if bok {
		// It was in the base, so the local side deleted it since agreement.
		if be.remoteMatches(rs) {
			// Remote unchanged → the local deletion propagates.
			return &Op{Kind: OpDeleteRemote, Path: p, IsDir: rs.kind == kindDir, Reason: "deleted locally"}, false
		}
		// Remote changed but local deleted → conflict.
		return r.conflictOp(p, lsAbsent, false, rs, true, "deleted locally, changed remotely")
	}
	// New remotely → download (mkdir for a directory).
	if rs.kind == kindDir {
		return &Op{Kind: OpMkdirLocal, Path: p, IsDir: true, Reason: "new remotely"}, false
	}
	return &Op{Kind: OpDownload, Path: p, IsSymlink: rs.isSymlink, Reason: "new remotely"}, false
}

// conflictOp resolves a conflict per the policy. hasLocal/hasRemote say which
// sides currently have the path (a deletion-vs-change conflict has only one).
func (r *Reconciler) conflictOp(p string, ls localState, hasLocal bool, rs remoteState, hasRemote bool, why string) (*Op, bool) {
	switch r.conflict {
	case PreferLocal:
		if hasLocal {
			if ls.kind == kindDir {
				return &Op{Kind: OpMkdirRemote, Path: p, IsDir: true, Reason: "conflict (" + why + ") → prefer-local"}, false
			}
			return &Op{Kind: OpUpload, Path: p, IsSymlink: ls.isSymlink, Reason: "conflict (" + why + ") → prefer-local"}, false
		}
		// Local is gone → prefer-local means propagate that deletion remotely.
		return &Op{Kind: OpDeleteRemote, Path: p, IsDir: rs.kind == kindDir, Reason: "conflict (" + why + ") → prefer-local (delete)"}, false
	case PreferRemote:
		if hasRemote {
			if rs.kind == kindDir {
				return &Op{Kind: OpMkdirLocal, Path: p, IsDir: true, Reason: "conflict (" + why + ") → prefer-remote"}, false
			}
			return &Op{Kind: OpDownload, Path: p, IsSymlink: rs.isSymlink, Reason: "conflict (" + why + ") → prefer-remote"}, false
		}
		return &Op{Kind: OpDeleteLocal, Path: p, IsDir: ls.kind == kindDir, Reason: "conflict (" + why + ") → prefer-remote (delete)"}, false
	default: // Skip
		return &Op{Kind: OpConflict, Path: p, Reason: "conflict (" + why + ") → skipped"}, true
	}
}

// isDelete reports whether an op kind removes something.
func isDelete(k OpKind) bool { return k == OpDeleteRemote || k == OpDeleteLocal }

// apply executes a plan, returning what it did. Per-operation errors are
// collected, not fatal.
func (r *Reconciler) apply(ctx context.Context, plan Plan) Result {
	var res Result
	a := &applier{r: r, dirIDs: map[string]provider.ItemID{}}
	for _, op := range plan.Ops {
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, err)
			return res
		}
		r.logf("sync: %s %q (%s)", op.Kind, op.Path, op.Reason)
		if err := a.do(ctx, op, &res); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("%s %q: %w", op.Kind, op.Path, err))
		}
	}
	return res
}

// applier carries per-pass state for applying operations, chiefly a cache of
// resolved remote directory IDs so a deep tree is not re-walked per file.
type applier struct {
	r      *Reconciler
	dirIDs map[string]provider.ItemID
}

// do dispatches one operation.
func (a *applier) do(ctx context.Context, op Op, res *Result) error {
	switch op.Kind {
	case OpMkdirRemote:
		if _, err := a.remoteDirID(ctx, op.Path); err != nil {
			return err
		}
		res.MkdirRemote++
		return nil
	case OpMkdirLocal:
		if err := a.mkdirLocal(ctx, op.Path); err != nil {
			return err
		}
		res.MkdirLocal++
		return nil
	case OpUpload:
		if err := a.upload(ctx, op.Path); err != nil {
			return err
		}
		res.Uploaded++
		return nil
	case OpDownload:
		if err := a.download(ctx, op.Path); err != nil {
			return err
		}
		res.Downloaded++
		return nil
	case OpDeleteRemote:
		if err := a.deleteRemote(ctx, op.Path); err != nil {
			return err
		}
		res.DeletedRemote++
		return nil
	case OpDeleteLocal:
		if err := a.deleteLocal(op.Path); err != nil {
			return err
		}
		res.DeletedLocal++
		return nil
	case OpConflict:
		res.Conflicts++
		return nil
	default:
		return fmt.Errorf("unknown op %v", op.Kind)
	}
}

// remoteDirID resolves the ItemID of the directory at slash path p under the
// provider root, creating it (and any missing ancestors) if absent. Results are
// cached for the pass.
func (a *applier) remoteDirID(ctx context.Context, p string) (provider.ItemID, error) {
	if p == "" {
		return a.r.prov.Root(ctx)
	}
	if id, ok := a.dirIDs[p]; ok {
		return id, nil
	}
	parentID, err := a.remoteDirID(ctx, parentPath(p))
	if err != nil {
		return "", err
	}
	name := baseName(p)
	if it, err := a.r.prov.Lookup(ctx, parentID, name); err == nil {
		if !it.IsDir {
			return "", fmt.Errorf("remote %q exists but is not a directory", p)
		}
		a.dirIDs[p] = it.ID
		return it.ID, nil
	} else if !errors.Is(err, provider.ErrNotFound) {
		return "", err
	}
	// Create the directory, stamping it with the local directory's attributes if
	// we have them.
	meta := a.localDirMeta(p)
	it, err := a.r.prov.CreateItem(ctx, parentID, provider.CreateRequest{Name: name, IsDir: true, Meta: meta})
	if err != nil {
		return "", err
	}
	a.dirIDs[p] = it.ID
	return it.ID, nil
}

// remoteItemID resolves the ItemID of the item (any kind) at path p.
func (a *applier) remoteItemID(ctx context.Context, p string) (provider.ItemID, error) {
	parentID, err := a.remoteDirID(ctx, parentPath(p))
	if err != nil {
		return "", err
	}
	it, err := a.r.prov.Lookup(ctx, parentID, baseName(p))
	if err != nil {
		return "", err
	}
	return it.ID, nil
}

// localDirMeta captures the attributes of the local directory at p, or a default
// directory mode if it cannot be stat'd (e.g. a directory that exists only
// remotely, created here to hold a downloaded child).
func (a *applier) localDirMeta(p string) pipeline.Metadata {
	abs := localAbs(a.r.root, p)
	if fi, err := os.Lstat(abs); err == nil {
		return fsmeta.Capture(abs, fi)
	}
	return pipeline.Metadata{Mode: uint32(0o755) | dirModeBit}
}

// upload creates or replaces the remote file/symlink at p from the local copy.
func (a *applier) upload(ctx context.Context, p string) error {
	abs := localAbs(a.r.root, p)
	fi, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	meta := fsmeta.Capture(abs, fi)
	parentID, err := a.remoteDirID(ctx, parentPath(p))
	if err != nil {
		return err
	}
	name := baseName(p)

	var contents io.Reader
	var closeFn func() error
	if !meta.IsSymlink() {
		f, err := os.Open(abs)
		if err != nil {
			return err
		}
		contents = f
		closeFn = f.Close
	}
	if closeFn != nil {
		defer closeFn()
	}

	// If an entry already exists at the destination, modify it in place (keeps the
	// stable ItemID) — unless its kind differs, in which case replace it.
	existing, lookupErr := a.r.prov.Lookup(ctx, parentID, name)
	switch {
	case lookupErr == nil && existing.IsDir:
		// Replacing a remote directory with a file: remove the directory first.
		if err := a.r.prov.DeleteItem(ctx, existing.ID); err != nil {
			return err
		}
	case lookupErr == nil:
		m := meta
		_, err := a.r.prov.ModifyItem(ctx, existing.ID, provider.ModifyRequest{Contents: contents, Meta: &m})
		return err
	case !errors.Is(lookupErr, provider.ErrNotFound):
		return lookupErr
	}
	_, err = a.r.prov.CreateItem(ctx, parentID, provider.CreateRequest{
		Name:     name,
		IsDir:    false,
		Meta:     meta,
		Contents: contents,
	})
	return err
}

// download creates or replaces the local file/symlink at p from the stored copy.
func (a *applier) download(ctx context.Context, p string) error {
	id, err := a.remoteItemID(ctx, p)
	if err != nil {
		return err
	}
	it, err := a.r.prov.Stat(ctx, id)
	if err != nil {
		return err
	}
	abs := localAbs(a.r.root, p)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	// If a directory currently sits where a file must go, remove it first.
	if fi, err := os.Lstat(abs); err == nil && fi.IsDir() {
		if err := os.RemoveAll(abs); err != nil {
			return err
		}
	}
	if it.Meta.IsSymlink() {
		return fsmeta.RestoreSymlink(abs, it.Meta)
	}
	f, err := os.Create(abs)
	if err != nil {
		return err
	}
	if _, err := a.r.prov.FetchContents(ctx, id, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsmeta.Restore(abs, it.Meta)
}

// mkdirLocal creates the local directory at p and restores its remote metadata.
func (a *applier) mkdirLocal(ctx context.Context, p string) error {
	abs := localAbs(a.r.root, p)
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	if id, err := a.remoteItemID(ctx, p); err == nil {
		if it, err := a.r.prov.Stat(ctx, id); err == nil {
			return fsmeta.Restore(abs, it.Meta)
		}
	}
	return nil
}

// deleteRemote removes the item (and, for a directory, its subtree) at p.
func (a *applier) deleteRemote(ctx context.Context, p string) error {
	id, err := a.remoteItemID(ctx, p)
	if err != nil {
		if errors.Is(err, provider.ErrNotFound) {
			return nil // already gone
		}
		return err
	}
	return a.r.prov.DeleteItem(ctx, id)
}

// deleteLocal removes the file or directory (recursively) at p.
func (a *applier) deleteLocal(p string) error {
	abs := localAbs(a.r.root, p)
	err := os.RemoveAll(abs)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// rebuildBase computes the new agreement after a pass by re-scanning both sides:
// every path now present on BOTH sides is recorded as agreed, except conflicted
// paths (skipped), whose previous base is preserved so the conflict resurfaces.
func (r *Reconciler) rebuildBase(ctx context.Context, oldBase *baseState, skipped map[string]bool) (*baseState, error) {
	local, err := scanLocal(r.root, r.ignore)
	if err != nil {
		return nil, err
	}
	remote, err := scanRemote(ctx, r.prov)
	if err != nil {
		return nil, err
	}
	nb := newBaseState()
	for p, ls := range local {
		rs, ok := remote[p]
		if !ok || ls.kind != rs.kind {
			continue
		}
		if skipped[p] {
			continue // handled below
		}
		nb.Entries[p] = agree(ls, rs)
	}
	// Preserve the prior base for any path left in conflict, so it is re-evaluated
	// next pass rather than being silently treated as agreed.
	for p := range skipped {
		if be, ok := oldBase.Entries[p]; ok {
			nb.Entries[p] = be
		}
	}
	return nb, nil
}

// dirModeBit is fs.ModeDir in the uint32 io/fs.FileMode representation
// pipeline.Metadata.Mode uses, so a default directory mode reads as a directory.
const dirModeBit = uint32(fs.ModeDir)
