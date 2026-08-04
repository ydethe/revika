package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// ErrNotFound is returned when an ItemID or a name does not resolve to an item.
var ErrNotFound = errors.New("provider: item not found")

// Manifest is the default Provider: it serves every framework call from
// revika's cap-addressed Merkle DAG (internal/manifest) over a store.Store, and
// records each mutation as a copy-on-write Graft that advances a signed
// RootPointer through a RootStore (Architecture §3.6/§3.8/§4). Nodes still see
// only content-addressed ciphertext shards; all naming, versioning, and identity
// live here on the User side.
//
// It holds the current root cap and sequence in memory, guarded by mu, so
// concurrent framework callbacks serialize on mutation while reads take a
// snapshot. Identity (stable ItemIDs) is tracked in ids.
type Manifest struct {
	store  store.Store
	cfg    pipeline.Config
	signer cap.SignKey
	roots  RootStore
	ids    *identity
	clock  func() int64

	mu   sync.Mutex
	root manifest.ReadCap
	seq  uint64
}

// Option configures a Manifest.
type Option func(*Manifest)

// WithConfig sets the encoding config for the manifest/directory blobs and file
// data this provider writes (default pipeline.DefaultConfig).
func WithConfig(cfg pipeline.Config) Option { return func(m *Manifest) { m.cfg = cfg } }

// WithClock overrides the source of the RootPointer timestamp (Unix ns). The
// default is time.Now; tests inject a fixed clock for deterministic signatures.
func WithClock(fn func() int64) Option { return func(m *Manifest) { m.clock = fn } }

// New builds a Manifest provider over store s, signing root pointers with
// signer and persisting them through roots. If roots already holds a pointer it
// is adopted (after verifying its signature and that it belongs to signer);
// otherwise an empty root directory is created and published at sequence 1.
func New(ctx context.Context, s store.Store, signer cap.SignKey, roots RootStore, opts ...Option) (*Manifest, error) {
	p := &Manifest{
		store:  s,
		cfg:    pipeline.DefaultConfig(),
		signer: signer,
		roots:  roots,
		ids:    newIdentity(),
		clock:  func() int64 { return time.Now().UnixNano() },
	}
	for _, o := range opts {
		o(p)
	}

	rp, ok, err := roots.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("provider: load root pointer: %w", err)
	}
	if ok {
		if !rp.Verify() {
			return nil, fmt.Errorf("provider: stored root pointer has an invalid signature")
		}
		if rp.Owner != signer.Public() {
			return nil, fmt.Errorf("provider: stored root pointer belongs to a different owner")
		}
		p.root = rp.Root
		p.seq = rp.Seq
		return p, nil
	}

	// Fresh namespace: an empty root directory, published at seq 1.
	empty, err := manifest.StoreDir(ctx, s, p.cfg, manifest.NewDir(pipeline.Metadata{Mode: dirMode()}))
	if err != nil {
		return nil, fmt.Errorf("provider: create root directory: %w", err)
	}
	if err := p.commit(ctx, empty); err != nil {
		return nil, err
	}
	return p, nil
}

// commit advances the sequence, signs a RootPointer for newRoot, persists it,
// and adopts newRoot as current. The caller must hold mu (or be in New, which
// runs single-threaded). On any failure the sequence is rolled back so it always
// matches the persisted pointer.
func (p *Manifest) commit(ctx context.Context, newRoot manifest.ReadCap) error {
	p.seq++
	rp, err := manifest.SignRoot(p.signer, newRoot, p.seq, p.clock())
	if err != nil {
		p.seq--
		return fmt.Errorf("provider: sign root pointer: %w", err)
	}
	if err := p.roots.Save(ctx, rp); err != nil {
		p.seq--
		return fmt.Errorf("provider: publish root pointer: %w", err)
	}
	p.root = newRoot
	return nil
}

// snapshot returns the current root cap and sequence for a read operation.
func (p *Manifest) snapshot() (manifest.ReadCap, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.root, p.seq
}

// Root implements Provider.
func (p *Manifest) Root(ctx context.Context) (ItemID, error) { return RootID, nil }

// Stat implements Provider, returning the full metadata record by reading the
// item's own blob.
func (p *Manifest) Stat(ctx context.Context, id ItemID) (Item, error) {
	path, ok := p.ids.pathFor(id)
	if !ok {
		return Item{}, ErrNotFound
	}
	root, _ := p.snapshot()

	if path == "" { // the root container
		d, err := manifest.LoadDir(ctx, p.store, root)
		if err != nil {
			return Item{}, err
		}
		return Item{
			ID: RootID, Parent: RootID, IsDir: true,
			Meta: d.Meta, Cap: root,
			Version: ItemVersion{Content: hashCap(root)},
			Caps:    capsFor(true, d.Meta.Mode),
		}, nil
	}

	e, err := p.entryOf(ctx, root, path)
	if err != nil {
		return Item{}, err
	}
	parent, _ := parentAndBase(path)
	it := p.itemFromEntry(parent, e)
	// Enrich with the full record from the item's own blob.
	switch e.Cap.Kind {
	case manifest.KindFile:
		fm, err := manifest.LoadFileManifest(ctx, p.store, e.Cap)
		if err != nil {
			return Item{}, err
		}
		it.Meta = fm.Meta
		it.Size = fm.Size
		if len(fm.Meta.ContentVersion) > 0 {
			it.Version = ItemVersion{Content: fm.Meta.ContentVersion, Meta: fm.Meta.MetaVersion}
		}
	case manifest.KindDir:
		d, err := manifest.LoadDir(ctx, p.store, e.Cap)
		if err != nil {
			return Item{}, err
		}
		it.Meta = d.Meta
	}
	return it, nil
}

// Lookup implements Provider.
func (p *Manifest) Lookup(ctx context.Context, parent ItemID, name string) (Item, error) {
	parentPath, ok := p.ids.pathFor(parent)
	if !ok {
		return Item{}, ErrNotFound
	}
	root, _ := p.snapshot()
	parentCap, err := manifest.Resolve(ctx, p.store, root, parentPath)
	if err != nil {
		return Item{}, err
	}
	if parentCap.Kind != manifest.KindDir {
		return Item{}, fmt.Errorf("provider: %q is not a directory", parentPath)
	}
	d, err := manifest.LoadDir(ctx, p.store, parentCap)
	if err != nil {
		return Item{}, err
	}
	e, ok := d.Lookup(name)
	if !ok {
		return Item{}, ErrNotFound
	}
	return p.itemFromEntry(parentPath, e), nil
}

// Enumerate implements Provider: the direct children of a directory as
// placeholder-ready Items, reading only the directory blob (no file content).
func (p *Manifest) Enumerate(ctx context.Context, dir ItemID) ([]Item, error) {
	dirPath, ok := p.ids.pathFor(dir)
	if !ok {
		return nil, ErrNotFound
	}
	root, _ := p.snapshot()
	dirCap, err := manifest.Resolve(ctx, p.store, root, dirPath)
	if err != nil {
		return nil, err
	}
	if dirCap.Kind != manifest.KindDir {
		return nil, fmt.Errorf("provider: %q is not a directory", dirPath)
	}
	d, err := manifest.LoadDir(ctx, p.store, dirCap)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(d.Entries))
	for _, e := range d.Entries {
		items = append(items, p.itemFromEntry(dirPath, e))
	}
	return items, nil
}

// CurrentAnchor implements Provider.
func (p *Manifest) CurrentAnchor(ctx context.Context) (SyncAnchor, error) {
	root, seq := p.snapshot()
	return SyncAnchor{Seq: seq, Root: root}, nil
}

// EnumerateChanges implements Provider by diffing the anchor's root against the
// current one over the Merkle DAG (diff.go).
func (p *Manifest) EnumerateChanges(ctx context.Context, since SyncAnchor) (ChangeSet, error) {
	root, seq := p.snapshot()
	changes, err := p.diff(ctx, since.Root, root)
	if err != nil {
		return ChangeSet{}, err
	}
	return ChangeSet{Changes: changes, Anchor: SyncAnchor{Seq: seq, Root: root}}, nil
}

// FetchContents implements Provider: on-demand hydration via pipeline.LoadFile.
func (p *Manifest) FetchContents(ctx context.Context, id ItemID, w io.Writer) (ItemVersion, error) {
	path, ok := p.ids.pathFor(id)
	if !ok {
		return ItemVersion{}, ErrNotFound
	}
	root, _ := p.snapshot()
	c, err := manifest.Resolve(ctx, p.store, root, path)
	if err != nil {
		return ItemVersion{}, err
	}
	if c.Kind != manifest.KindFile {
		return ItemVersion{}, fmt.Errorf("provider: %q is not a file", path)
	}
	fm, err := manifest.LoadFileManifest(ctx, p.store, c)
	if err != nil {
		return ItemVersion{}, err
	}
	// A symlink's "content" is its target (metadata), not shard bytes, so there
	// is nothing to stream; the caller reads Meta.SymlinkTarget from Stat.
	if !fm.Meta.IsSymlink() {
		if err := pipeline.LoadFile(ctx, p.store, fm, w); err != nil {
			return ItemVersion{}, fmt.Errorf("provider: hydrate %q: %w", path, err)
		}
	}
	return ItemVersion{Content: fm.Meta.ContentVersion, Meta: fm.Meta.MetaVersion}, nil
}

// Evict implements Provider. The manifest backing keeps no local copy of content
// (it is remote by nature), so eviction is a no-op; a mount with a placeholder
// cache overrides this to drop cached bytes.
func (p *Manifest) Evict(ctx context.Context, id ItemID) error {
	if _, ok := p.ids.pathFor(id); !ok {
		return ErrNotFound
	}
	return nil
}

// CreateItem implements Provider.
func (p *Manifest) CreateItem(ctx context.Context, parent ItemID, req CreateRequest) (Item, error) {
	if req.Name == "" {
		return Item{}, fmt.Errorf("provider: create needs a name")
	}
	parentPath, ok := p.ids.pathFor(parent)
	if !ok {
		return Item{}, ErrNotFound
	}
	childPath := join(parentPath, req.Name)

	p.mu.Lock()
	defer p.mu.Unlock()

	childCap, stat, err := p.buildChild(ctx, req.Name, req.IsDir, req.Meta, req.Contents)
	if err != nil {
		return Item{}, err
	}
	newRoot, err := manifest.Graft(ctx, p.store, p.cfg, p.root, childPath, childCap, stat)
	if err != nil {
		return Item{}, fmt.Errorf("provider: graft %q: %w", childPath, err)
	}
	if err := p.commit(ctx, newRoot); err != nil {
		return Item{}, err
	}
	return p.itemFromEntry(parentPath, manifest.Entry{Name: req.Name, Cap: childCap, Stat: stat}), nil
}

// ModifyItem implements Provider: replace content and/or attributes in place.
func (p *Manifest) ModifyItem(ctx context.Context, id ItemID, req ModifyRequest) (Item, error) {
	path, ok := p.ids.pathFor(id)
	if !ok {
		return Item{}, ErrNotFound
	}
	if path == "" {
		return Item{}, fmt.Errorf("provider: cannot modify the root")
	}
	if req.Contents == nil && req.Meta == nil {
		return p.Stat(ctx, id) // nothing to change
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	e, err := p.entryOf(ctx, p.root, path)
	if err != nil {
		return Item{}, err
	}
	var newCap manifest.ReadCap
	var stat manifest.StatCache
	switch e.Cap.Kind {
	case manifest.KindDir:
		d, err := manifest.LoadDir(ctx, p.store, e.Cap)
		if err != nil {
			return Item{}, err
		}
		if req.Meta != nil {
			d.Meta = *req.Meta
		}
		newCap, err = manifest.StoreDir(ctx, p.store, p.cfg, d)
		if err != nil {
			return Item{}, err
		}
		stat = manifest.StatCache{Kind: manifest.KindDir, Mode: d.Meta.Mode, ModTimeNS: d.Meta.ModTimeNS}
	case manifest.KindFile:
		fm, err := manifest.LoadFileManifest(ctx, p.store, e.Cap)
		if err != nil {
			return Item{}, err
		}
		meta := fm.Meta
		if req.Meta != nil {
			meta = *req.Meta
		}
		if req.Contents != nil {
			nfm, err := pipeline.StoreFile(ctx, p.store, p.cfg, req.Contents)
			if err != nil {
				return Item{}, err
			}
			nfm.Name = fm.Name
			nfm.Meta = meta
			fm = nfm
		} else {
			fm.Meta = meta
		}
		pipeline.DeriveVersions(&fm)
		newCap, err = manifest.StoreFileManifest(ctx, p.store, p.cfg, fm)
		if err != nil {
			return Item{}, err
		}
		stat = statFromManifest(fm)
	}

	newRoot, err := manifest.Graft(ctx, p.store, p.cfg, p.root, path, newCap, stat)
	if err != nil {
		return Item{}, fmt.Errorf("provider: graft %q: %w", path, err)
	}
	if err := p.commit(ctx, newRoot); err != nil {
		return Item{}, err
	}
	parent, name := parentAndBase(path)
	return p.itemFromEntry(parent, manifest.Entry{Name: name, Cap: newCap, Stat: stat}), nil
}

// DeleteItem implements Provider.
func (p *Manifest) DeleteItem(ctx context.Context, id ItemID) error {
	path, ok := p.ids.pathFor(id)
	if !ok {
		return ErrNotFound
	}
	if path == "" {
		return fmt.Errorf("provider: cannot delete the root")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	newRoot, err := manifest.GraftRemove(ctx, p.store, p.cfg, p.root, path)
	if err != nil {
		return fmt.Errorf("provider: remove %q: %w", path, err)
	}
	if err := p.commit(ctx, newRoot); err != nil {
		return err
	}
	p.ids.remove(path)
	return nil
}

// Rename implements Provider: move and/or rename, keeping the ID stable.
func (p *Manifest) Rename(ctx context.Context, id ItemID, newParent ItemID, newName string) (Item, error) {
	oldPath, ok := p.ids.pathFor(id)
	if !ok {
		return Item{}, ErrNotFound
	}
	if oldPath == "" {
		return Item{}, fmt.Errorf("provider: cannot rename the root")
	}
	if newName == "" {
		return Item{}, fmt.Errorf("provider: rename needs a new name")
	}
	newParentPath, ok := p.ids.pathFor(newParent)
	if !ok {
		return Item{}, ErrNotFound
	}
	newPath := join(newParentPath, newName)
	if newPath == oldPath {
		return p.Stat(ctx, id)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	e, err := p.entryOf(ctx, p.root, oldPath)
	if err != nil {
		return Item{}, err
	}
	// Copy-on-write: graft the same child cap at the destination, then remove the
	// source. A file's cap is content-addressed, so the moved item keeps its
	// shards and versions untouched — only two directory blobs are rewritten.
	grafted, err := manifest.Graft(ctx, p.store, p.cfg, p.root, newPath, e.Cap, e.Stat)
	if err != nil {
		return Item{}, fmt.Errorf("provider: graft %q: %w", newPath, err)
	}
	newRoot, err := manifest.GraftRemove(ctx, p.store, p.cfg, grafted, oldPath)
	if err != nil {
		return Item{}, fmt.Errorf("provider: remove %q: %w", oldPath, err)
	}
	if err := p.commit(ctx, newRoot); err != nil {
		return Item{}, err
	}
	p.ids.rename(oldPath, newPath)
	return p.itemFromEntry(newParentPath, manifest.Entry{Name: newName, Cap: e.Cap, Stat: e.Stat}), nil
}

// buildChild stores a new child (file, directory, or symlink) and returns its
// cap and the StatCache to record in the parent. The caller holds mu.
func (p *Manifest) buildChild(ctx context.Context, name string, isDir bool, meta pipeline.Metadata, contents io.Reader) (manifest.ReadCap, manifest.StatCache, error) {
	if isDir {
		c, err := manifest.StoreDir(ctx, p.store, p.cfg, manifest.NewDir(meta))
		if err != nil {
			return manifest.ReadCap{}, manifest.StatCache{}, err
		}
		return c, manifest.StatCache{Kind: manifest.KindDir, Mode: meta.Mode, ModTimeNS: meta.ModTimeNS}, nil
	}
	var fm pipeline.FileManifest
	if meta.IsSymlink() || contents == nil {
		fm = pipeline.FileManifest{Params: p.cfg} // symlink/empty: no data shards
	} else {
		var err error
		fm, err = pipeline.StoreFile(ctx, p.store, p.cfg, contents)
		if err != nil {
			return manifest.ReadCap{}, manifest.StatCache{}, err
		}
	}
	fm.Name = name
	fm.Meta = meta
	pipeline.DeriveVersions(&fm)
	c, err := manifest.StoreFileManifest(ctx, p.store, p.cfg, fm)
	if err != nil {
		return manifest.ReadCap{}, manifest.StatCache{}, err
	}
	return c, statFromManifest(fm), nil
}

// entryOf loads the directory containing path (under root) and returns path's
// entry. It errors if path is the root or does not exist.
func (p *Manifest) entryOf(ctx context.Context, root manifest.ReadCap, path string) (manifest.Entry, error) {
	if path == "" {
		return manifest.Entry{}, fmt.Errorf("provider: the root has no entry")
	}
	parent, base := parentAndBase(path)
	parentCap, err := manifest.Resolve(ctx, p.store, root, parent)
	if err != nil {
		return manifest.Entry{}, err
	}
	if parentCap.Kind != manifest.KindDir {
		return manifest.Entry{}, fmt.Errorf("provider: %q is not a directory", parent)
	}
	d, err := manifest.LoadDir(ctx, p.store, parentCap)
	if err != nil {
		return manifest.Entry{}, err
	}
	e, ok := d.Lookup(base)
	if !ok {
		return manifest.Entry{}, ErrNotFound
	}
	return e, nil
}

// itemFromEntry builds a placeholder Item from a directory entry and its parent
// path, minting/looking up the stable IDs. Meta is the light subset the parent
// caches (mode + mtime); Stat returns the full record.
func (p *Manifest) itemFromEntry(parentPath string, e manifest.Entry) Item {
	childPath := join(parentPath, e.Name)
	isDir := e.Cap.Kind == manifest.KindDir
	ver := ItemVersion{Content: e.Stat.ContentVersion, Meta: e.Stat.MetaVersion}
	if len(ver.Content) == 0 {
		ver.Content = hashCap(e.Cap) // dirs (and any entry lacking a token) key off the cap
	}
	return Item{
		ID:      p.ids.idFor(childPath),
		Parent:  p.ids.idFor(parentPath),
		Name:    e.Name,
		IsDir:   isDir,
		IsLink:  fs.FileMode(e.Stat.Mode)&fs.ModeSymlink != 0,
		Size:    e.Stat.Size,
		Version: ver,
		Meta:    pipeline.Metadata{Mode: e.Stat.Mode, ModTimeNS: e.Stat.ModTimeNS},
		Caps:    capsFor(isDir, e.Stat.Mode),
		Cap:     e.Cap,
	}
}

// statFromManifest builds the StatCache a directory keeps for a file child, so a
// reader can serve readdir/getattr without hydrating the file (§3.8).
func statFromManifest(fm pipeline.FileManifest) manifest.StatCache {
	return manifest.StatCache{
		Kind:           manifest.KindFile,
		Size:           fm.Size,
		Mode:           fm.Meta.Mode,
		ModTimeNS:      fm.Meta.ModTimeNS,
		ContentVersion: fm.Meta.ContentVersion,
		MetaVersion:    fm.Meta.MetaVersion,
	}
}

// capsFor derives the permission bitset shown to the framework from an item's
// kind and mode. Directories add child-listing and child-creation; the owner may
// always rename/reparent/delete their own items.
func capsFor(isDir bool, mode uint32) Capabilities {
	caps := CapRead | CapRename | CapReparent | CapDelete
	if isDir {
		caps |= CapWrite | CapAddSubItems | CapEnumerate
	} else if mode == 0 || fs.FileMode(mode).Perm()&0o200 != 0 {
		caps |= CapWrite
	}
	return caps
}

// hashCap derives a stable content-version token from a cap: because a cap
// commits (via its content-addressed shard IDs) to the exact blob bytes, its
// hash changes exactly when the blob does. Used for directories and for any
// entry that carries no precomputed token.
func hashCap(c manifest.ReadCap) []byte {
	b, err := c.MarshalBinary()
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(b)
	return sum[:16]
}

// capEqual reports whether two caps address the identical blob (hence the
// identical subtree). Equal caps let diff prune an unchanged subtree.
func capEqual(a, b manifest.ReadCap) bool {
	ab, err1 := a.MarshalBinary()
	bb, err2 := b.MarshalBinary()
	return err1 == nil && err2 == nil && bytes.Equal(ab, bb)
}

// dirMode is the mode recorded for a directory the provider creates itself.
func dirMode() uint32 { return uint32(fs.ModeDir | 0o755) }

// join returns the child path for name under parentPath ("" is the root).
func join(parentPath, name string) string {
	if parentPath == "" {
		return name
	}
	return parentPath + "/" + name
}

// parentAndBase splits a slash path into its parent path and final component.
func parentAndBase(path string) (string, string) {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "", path
	}
	return path[:i], path[i+1:]
}
