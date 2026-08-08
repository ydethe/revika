package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"revika/internal/pipeline"
	"revika/internal/store"
)

// StatCache is the small, non-secret snapshot a directory keeps for each child
// so a mount can serve readdir/getattr without hydrating (fetching + decrypting)
// the child blob — the placeholder model of Architecture §3.8. It duplicates a
// few fields that also live in the child's own manifest; the child remains
// authoritative, this is a cache the parent refreshes on copy-on-write.
type StatCache struct {
	Kind           Kind   `json:"kind"`
	Size           int64  `json:"size,omitempty"`
	Mode           uint32 `json:"mode,omitempty"`
	ModTimeNS      int64  `json:"mtime_ns,omitempty"`
	ContentVersion []byte `json:"content_version,omitempty"` // base64
	MetaVersion    []byte `json:"meta_version,omitempty"`    // base64
}

// Entry binds a name to a child cap inside a directory. The Name is the
// authoritative filesystem name (the manifest blob it points at is nameless);
// renaming rewrites this Entry, not the child. Stat lets readdir/getattr be
// served from the parent alone.
type Entry struct {
	Name string    `json:"name"`
	Cap  ReadCap   `json:"cap"`
	Stat StatCache `json:"stat"`
}

// DirManifest is a directory: its own filesystem Meta plus a set of named child
// entries (files or subdirectories), each addressed by a cap. Serialized and
// stored as a KindDir blob, it is one node of the Merkle DAG — its cap commits to
// every child cap, hence to the whole subtree. Entries are kept sorted by Name so
// the serialized bytes are canonical (a directory re-encoded yields identical
// bytes) and lookups can binary-search.
type DirManifest struct {
	Meta    pipeline.Metadata
	Entries []Entry
}

// NewDir returns an empty directory carrying meta as its own attributes.
func NewDir(meta pipeline.Metadata) DirManifest { return DirManifest{Meta: meta} }

// Lookup returns the entry named name, if present.
func (d DirManifest) Lookup(name string) (Entry, bool) {
	i := sort.Search(len(d.Entries), func(i int) bool { return d.Entries[i].Name >= name })
	if i < len(d.Entries) && d.Entries[i].Name == name {
		return d.Entries[i], true
	}
	return Entry{}, false
}

// Upsert inserts e, or replaces the existing entry with the same Name, keeping
// Entries sorted. It returns a new DirManifest; the receiver is left unchanged so
// copy-on-write callers never mutate a shared directory in place.
func (d DirManifest) Upsert(e Entry) DirManifest {
	out := DirManifest{Meta: d.Meta, Entries: make([]Entry, 0, len(d.Entries)+1)}
	replaced := false
	for _, cur := range d.Entries {
		if cur.Name == e.Name {
			out.Entries = append(out.Entries, e)
			replaced = true
		} else {
			out.Entries = append(out.Entries, cur)
		}
	}
	if !replaced {
		out.Entries = append(out.Entries, e)
		sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Name < out.Entries[j].Name })
	}
	return out
}

// Remove returns a copy of d without the entry named name, and whether one was
// removed.
func (d DirManifest) Remove(name string) (DirManifest, bool) {
	out := DirManifest{Meta: d.Meta, Entries: make([]Entry, 0, len(d.Entries))}
	removed := false
	for _, cur := range d.Entries {
		if cur.Name == name {
			removed = true
			continue
		}
		out.Entries = append(out.Entries, cur)
	}
	return out, removed
}

// dirManifestJSON is the serialized form of a DirManifest. Entries carry their
// own hex/base64 handling via ReadCap and StatCache; pipeline.Metadata marshals
// directly (see file.go).
type dirManifestJSON struct {
	Version int               `json:"version"`
	Meta    pipeline.Metadata `json:"meta,omitzero"`
	Entries []Entry           `json:"entries"`
}

const dirManifestVersion = 1

// EncodeDir renders d as canonical JSON, with entries sorted by Name so the same
// directory content always produces the same bytes.
func EncodeDir(d DirManifest) ([]byte, error) {
	entries := make([]Entry, len(d.Entries))
	copy(entries, d.Entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return json.Marshal(dirManifestJSON{Version: dirManifestVersion, Meta: d.Meta, Entries: entries})
}

// DecodeDir parses JSON produced by EncodeDir.
func DecodeDir(data []byte) (DirManifest, error) {
	var jm dirManifestJSON
	if err := json.Unmarshal(data, &jm); err != nil {
		return DirManifest{}, fmt.Errorf("manifest: parse directory: %w", err)
	}
	if jm.Version < 1 || jm.Version > dirManifestVersion {
		return DirManifest{}, fmt.Errorf("manifest: unsupported directory version %d (want 1..%d)", jm.Version, dirManifestVersion)
	}
	sort.Slice(jm.Entries, func(i, j int) bool { return jm.Entries[i].Name < jm.Entries[j].Name })
	return DirManifest{Meta: jm.Meta, Entries: jm.Entries}, nil
}

// StoreDir serializes d and stores it as an immutable, encrypted KindDir blob,
// returning the cap that addresses it. cfg controls the directory blob's own
// encoding.
func StoreDir(ctx context.Context, s store.Store, cfg pipeline.Config, d DirManifest) (ReadCap, error) {
	data, err := EncodeDir(d)
	if err != nil {
		return ReadCap{}, fmt.Errorf("manifest: encode directory: %w", err)
	}
	return putBlob(ctx, s, cfg, KindDir, data)
}

// LoadDir fetches and decrypts the KindDir blob a cap points at.
func LoadDir(ctx context.Context, s store.Store, c ReadCap) (DirManifest, error) {
	data, err := getBlob(ctx, s, c, KindDir)
	if err != nil {
		return DirManifest{}, err
	}
	return DecodeDir(data)
}

// splitPath cleans a slash-separated path and returns its components. It rejects
// paths that escape the root ("..") — a namespace is a DAG rooted at one cap, not
// a place you can climb out of.
func splitPath(p string) ([]string, error) {
	clean := path.Clean("/" + p) // force root-relative, collapse ./ and //
	if clean == "/" {
		return nil, nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	if slices.Contains(parts, "..") {
		return nil, fmt.Errorf("manifest: path %q escapes the root", p)
	}
	return parts, nil
}

// Resolve walks a slash-separated path from a root directory cap and returns the
// cap of the target (a file or a subdirectory). An empty path returns root
// itself. Only open/read on the returned cap touches the network beyond the
// directories on the path — the on-demand hydration model of §3.8.
func Resolve(ctx context.Context, s store.Store, root ReadCap, p string) (ReadCap, error) {
	parts, err := splitPath(p)
	if err != nil {
		return ReadCap{}, err
	}
	cur := root
	for i, name := range parts {
		if cur.Kind != KindDir {
			return ReadCap{}, fmt.Errorf("manifest: %q is not a directory", strings.Join(parts[:i], "/"))
		}
		d, err := LoadDir(ctx, s, cur)
		if err != nil {
			return ReadCap{}, err
		}
		e, ok := d.Lookup(name)
		if !ok {
			return ReadCap{}, fmt.Errorf("manifest: %q not found", strings.Join(parts[:i+1], "/"))
		}
		cur = e.Cap
	}
	return cur, nil
}

// ResolveEntry walks p like Resolve but returns the target's directory Entry —
// its cap plus the parent's cached StatCache — so a caller can copy a node
// while preserving its recorded size/mode/mtime. The root itself (empty path)
// has no parent Entry, so it is reported as a nameless KindDir entry carrying
// the root cap and a bare directory stat.
func ResolveEntry(ctx context.Context, s store.Store, root ReadCap, p string) (Entry, error) {
	parts, err := splitPath(p)
	if err != nil {
		return Entry{}, err
	}
	if len(parts) == 0 {
		return Entry{Name: "", Cap: root, Stat: StatCache{Kind: KindDir}}, nil
	}
	cur := root
	for i, name := range parts {
		if cur.Kind != KindDir {
			return Entry{}, fmt.Errorf("manifest: %q is not a directory", strings.Join(parts[:i], "/"))
		}
		d, err := LoadDir(ctx, s, cur)
		if err != nil {
			return Entry{}, err
		}
		e, ok := d.Lookup(name)
		if !ok {
			return Entry{}, fmt.Errorf("manifest: %q not found", strings.Join(parts[:i+1], "/"))
		}
		if i == len(parts)-1 {
			return e, nil
		}
		cur = e.Cap
	}
	return Entry{}, fmt.Errorf("manifest: %q not found", p) // unreachable: loop returns on last part
}

// Graft returns a new root cap with the child cap bound at path p, rewriting
// every directory on the path to p (copy-on-write up the Merkle tree, §3.8):
// a new child manifest → a new parent directory → … → a new root. Sibling
// subtrees keep their caps and shards untouched. Missing intermediate
// directories are created empty. stat is the StatCache recorded for the grafted
// child (files supply size/mode/versions; a nil/zero stat is fine for a
// directory, whose kind is taken from child.Kind).
//
// Graft is the single mutation primitive behind put, rename (graft the same
// child cap under a new name, then Remove the old), and delete (see GraftRemove).
func Graft(ctx context.Context, s store.Store, cfg pipeline.Config, root ReadCap, p string, child ReadCap, stat StatCache) (ReadCap, error) {
	parts, err := splitPath(p)
	if err != nil {
		return ReadCap{}, err
	}
	if len(parts) == 0 {
		return ReadCap{}, fmt.Errorf("manifest: cannot graft onto the root path")
	}
	return graft(ctx, s, cfg, root, parts, child, stat)
}

func graft(ctx context.Context, s store.Store, cfg pipeline.Config, dirCap ReadCap, parts []string, child ReadCap, stat StatCache) (ReadCap, error) {
	d, err := LoadDir(ctx, s, dirCap)
	if err != nil {
		return ReadCap{}, err
	}
	name := parts[0]
	if len(parts) == 1 {
		stat.Kind = child.Kind
		d = d.Upsert(Entry{Name: name, Cap: child, Stat: stat})
		return StoreDir(ctx, s, cfg, d)
	}

	// Descend into (or create) the intermediate directory, recurse, then rewrite
	// this level's entry to point at the rewritten subdirectory.
	var subCap ReadCap
	if e, ok := d.Lookup(name); ok {
		if e.Cap.Kind != KindDir {
			return ReadCap{}, fmt.Errorf("manifest: %q is not a directory", name)
		}
		subCap = e.Cap
	} else {
		subCap, err = StoreDir(ctx, s, cfg, NewDir(pipeline.Metadata{}))
		if err != nil {
			return ReadCap{}, err
		}
	}
	newSub, err := graft(ctx, s, cfg, subCap, parts[1:], child, stat)
	if err != nil {
		return ReadCap{}, err
	}
	d = d.Upsert(Entry{Name: name, Cap: newSub, Stat: StatCache{Kind: KindDir}})
	return StoreDir(ctx, s, cfg, d)
}

// GraftRemove returns a new root cap with the entry at path p removed, rewriting
// the directories on the path (copy-on-write, like Graft). It returns an error
// if the entry does not exist.
func GraftRemove(ctx context.Context, s store.Store, cfg pipeline.Config, root ReadCap, p string) (ReadCap, error) {
	parts, err := splitPath(p)
	if err != nil {
		return ReadCap{}, err
	}
	if len(parts) == 0 {
		return ReadCap{}, fmt.Errorf("manifest: cannot remove the root path")
	}
	return graftRemove(ctx, s, cfg, root, parts)
}

func graftRemove(ctx context.Context, s store.Store, cfg pipeline.Config, dirCap ReadCap, parts []string) (ReadCap, error) {
	d, err := LoadDir(ctx, s, dirCap)
	if err != nil {
		return ReadCap{}, err
	}
	name := parts[0]
	if len(parts) == 1 {
		out, removed := d.Remove(name)
		if !removed {
			return ReadCap{}, fmt.Errorf("manifest: %q not found", name)
		}
		return StoreDir(ctx, s, cfg, out)
	}
	e, ok := d.Lookup(name)
	if !ok {
		return ReadCap{}, fmt.Errorf("manifest: %q not found", name)
	}
	if e.Cap.Kind != KindDir {
		return ReadCap{}, fmt.Errorf("manifest: %q is not a directory", name)
	}
	newSub, err := graftRemove(ctx, s, cfg, e.Cap, parts[1:])
	if err != nil {
		return ReadCap{}, err
	}
	d = d.Upsert(Entry{Name: name, Cap: newSub, Stat: StatCache{Kind: KindDir}})
	return StoreDir(ctx, s, cfg, d)
}
