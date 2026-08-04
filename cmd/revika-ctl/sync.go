package main

// sync.go adds a lazy, two-phase materialization of a stored directory tree,
// the on-demand hydration model of Architecture §3.8:
//
//   - `sync`    walks the directory Merkle DAG and recreates the namespace
//               locally — directories, empty file placeholders, and symlinks —
//               fetching ONLY directory blobs, never a regular file's content.
//               It leaves a .revika-sync.json index mapping each placeholder to
//               its (nameless, content-addressed) file cap.
//   - `hydrate` fills chosen placeholders with real content, resolving their
//               caps from that index (no directory re-walk) and fetching only
//               the wanted files' shards.
//
// This is the client-side counterpart of a cloud-storage "online-only" file:
// the whole tree is browsable immediately at near-zero transfer, and bytes are
// pulled only for the files you actually open.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// syncIndexName is the local sidecar `sync` writes at the destination root and
// `hydrate` reads. It records the tree root cap and, per placeholder, the file
// cap needed to hydrate it. Hidden so it stays out of the way of a normal
// listing; like .git it is local state, not part of the stored tree.
const syncIndexName = ".revika-sync.json"

const syncIndexVersion = 1

// syncFile is one placeholder recorded in the index: where it lives (slash path
// relative to the sync root), the file cap that hydrates it, and whether it has
// been hydrated yet. The cap is a read-capability (it carries decryption keys),
// so the index is as secret as a manifest — written 0600.
type syncFile struct {
	Path     string           `json:"path"`
	Cap      manifest.ReadCap `json:"cap"`
	Size     int64            `json:"size,omitempty"`
	Symlink  bool             `json:"symlink,omitempty"`
	Hydrated bool             `json:"hydrated"`
}

// syncIndex is the .revika-sync.json sidecar: the tree's root cap plus one entry
// per file placeholder, sorted by Path for stable output and binary lookups.
type syncIndex struct {
	Version int              `json:"version"`
	Root    manifest.ReadCap `json:"root"`
	Files   []syncFile       `json:"files"`
}

// cmdSync materializes the namespace of a stored directory tree without
// downloading file content. It resolves a directory root cap (your own via
// -manifest, or a shared one via -cap/-key) and recreates the tree under -o,
// fetching only the directory blobs that describe the shape.
func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	node := fs.String("node", "", "fetch directory blobs from this single node multiaddr (with /p2p/<peerid>)")
	manifestPath := fs.String("manifest", "", "directory root cap file to read (your own tree)")
	capPath := fs.String("cap", "", "wrapped directory cap file to read (a shared tree); requires -key")
	keyPath := fs.String("key", "", "your private key file, to unwrap -cap")
	out := fs.String("o", "", "destination directory to materialize the namespace into (required)")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); discovers directory-blob providers")
	mdns := fs.Bool("mdns", false, "discover providers via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("sync needs -o <destination directory>")
	}

	ctx := context.Background()
	s, closer, err := getBackend(ctx, *node, bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	// A tree is the only thing worth syncing lazily; a single file has no
	// namespace to browse, so route it to plain `get`.
	fm, dirCap, err := resolveGetTarget(ctx, s, *manifestPath, *capPath, *keyPath)
	if err != nil {
		return err
	}
	if dirCap == nil {
		_ = fm
		return fmt.Errorf("sync needs a directory root cap; this capability is a single file — use `get` instead")
	}
	return syncTree(ctx, s, *dirCap, *out)
}

// syncTree recreates the tree rooted at root under dest as a browsable namespace
// (directories + placeholders + symlinks) and writes the .revika-sync.json index.
func syncTree(ctx context.Context, s store.Store, root manifest.ReadCap, dest string) error {
	if root.Kind != manifest.KindDir {
		return fmt.Errorf("root cap is a %s, not a directory", root.Kind)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	idx := &syncIndex{Version: syncIndexVersion, Root: root}
	nDirs, nFiles, err := syncDir(ctx, s, root, dest, "", idx)
	if err != nil {
		return fmt.Errorf("sync tree: %w", err)
	}
	if err := writeSyncIndex(dest, idx); err != nil {
		return fmt.Errorf("write sync index: %w", err)
	}

	var deferred int64
	stubs := 0
	for _, f := range idx.Files {
		if !f.Hydrated {
			deferred += f.Size
			stubs++
		}
	}
	fmt.Printf("Synced %d director(y|ies) and %d file(s) into %s\n", nDirs, nFiles, dest)
	fmt.Printf("%d placeholder(s) not yet hydrated (%d bytes deferred)\n", stubs, deferred)
	fmt.Printf("Index: %s\n", filepath.Join(dest, syncIndexName))
	fmt.Fprintln(os.Stderr, "Hydrate a file or subtree with: revika-ctl hydrate <path> (same -node/-bootstrap/-mdns backend)")
	return nil
}

// syncDir recreates one directory blob's entries under destAbs: sub-directories
// recurse, symlinks are materialized (their "content" is a target path, so they
// are structural and cheap), and regular files become empty placeholders whose
// caps are recorded in idx. relPrefix is the slash path of destAbs within the
// sync root. It returns the number of sub-directories and files seen.
func syncDir(ctx context.Context, s store.Store, dirCap manifest.ReadCap, destAbs, relPrefix string, idx *syncIndex) (int, int, error) {
	d, err := manifest.LoadDir(ctx, s, dirCap)
	if err != nil {
		return 0, 0, err
	}
	nDirs, nFiles := 0, 0
	for _, e := range d.Entries {
		if err := safeEntryName(e.Name); err != nil {
			return nDirs, nFiles, err
		}
		childAbs := filepath.Join(destAbs, e.Name)
		childRel := e.Name
		if relPrefix != "" {
			childRel = relPrefix + "/" + e.Name
		}
		switch e.Cap.Kind {
		case manifest.KindDir:
			if err := os.MkdirAll(childAbs, 0o755); err != nil {
				return nDirs, nFiles, err
			}
			dd, ff, err := syncDir(ctx, s, e.Cap, childAbs, childRel, idx)
			nDirs += 1 + dd
			nFiles += ff
			if err != nil {
				return nDirs, nFiles, err
			}
		case manifest.KindFile:
			// A symlink's content is just its target path; materialize it now so
			// the namespace is correctly typed. Regular files stay empty stubs.
			if fs.FileMode(e.Stat.Mode)&fs.ModeSymlink != 0 {
				if _, err := restoreFile(ctx, s, e.Cap, childAbs); err != nil {
					return nDirs, nFiles, err
				}
				idx.Files = append(idx.Files, syncFile{Path: childRel, Cap: e.Cap, Symlink: true, Hydrated: true})
			} else {
				if err := writePlaceholder(childAbs, e.Stat); err != nil {
					return nDirs, nFiles, err
				}
				idx.Files = append(idx.Files, syncFile{Path: childRel, Cap: e.Cap, Size: e.Stat.Size, Hydrated: false})
			}
			nFiles++
		default:
			return nDirs, nFiles, fmt.Errorf("entry %q has unknown cap kind %s", e.Name, e.Cap.Kind)
		}
	}
	// Restore the directory's own metadata after its children exist.
	if err := restoreMetadata(destAbs, d.Meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial metadata restore for %s: %v\n", destAbs, err)
	}
	return nDirs, nFiles, nil
}

// writePlaceholder creates an empty stand-in file for a not-yet-hydrated entry,
// stamped with the mode and mtime the directory cached for it so a listing shows
// the real attributes. No file content is fetched.
func writePlaceholder(path string, stat manifest.StatCache) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Only mode/mtime are known from the parent's StatCache; the full metadata
	// (owner/xattrs) is restored on hydrate, when the file manifest is fetched.
	meta := pipeline.Metadata{Mode: stat.Mode, ModTimeNS: stat.ModTimeNS}
	if err := restoreMetadata(path, meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial metadata restore for %s: %v\n", path, err)
	}
	return nil
}

// cmdHydrate fills previously-synced placeholders with real content. Each <path>
// is a filesystem path inside a synced tree (a placeholder file, or a directory
// to hydrate its whole subtree); the sync root is found by ascending to the
// nearest .revika-sync.json, or set explicitly with -C. With -C and no paths,
// the entire tree is hydrated.
func cmdHydrate(args []string) error {
	fs := flag.NewFlagSet("hydrate", flag.ExitOnError)
	node := fs.String("node", "", "fetch shards from this single node multiaddr (with /p2p/<peerid>)")
	root := fs.String("C", "", "sync directory (default: auto-detected by ascending from each <path> to the nearest "+syncIndexName+")")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); discovers shard providers")
	mdns := fs.Bool("mdns", false, "discover shard providers via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := fs.Args()

	// Group the requested paths by the sync root they belong to, so each index is
	// loaded and rewritten once even if several paths target the same tree.
	groups, err := planHydrate(*root, paths)
	if err != nil {
		return err
	}

	ctx := context.Background()
	s, closer, err := getBackend(ctx, *node, bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	total := 0
	for _, g := range groups {
		n, err := runHydrateGroup(ctx, s, g)
		total += n
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Hydrated %d file(s)\n", total)
	return nil
}

// hydrateGroup is one sync root plus the set of slash targets to hydrate within
// it ("" means the whole tree).
type hydrateGroup struct {
	root    string // sync-root directory (absolute)
	idx     *syncIndex
	targets []string
}

// planHydrate resolves the CLI paths into per-root hydration groups. With an
// explicit -C root, each path is taken relative to it (no paths => the whole
// tree). Otherwise each path's sync root is found by ascending to the nearest
// index file, and paths are grouped by the root they land in.
func planHydrate(explicitRoot string, paths []string) ([]*hydrateGroup, error) {
	byRoot := map[string]*hydrateGroup{}
	var order []*hydrateGroup

	group := func(rootAbs string) (*hydrateGroup, error) {
		if g := byRoot[rootAbs]; g != nil {
			return g, nil
		}
		idx, err := readSyncIndex(rootAbs)
		if err != nil {
			return nil, err
		}
		g := &hydrateGroup{root: rootAbs, idx: idx}
		byRoot[rootAbs] = g
		order = append(order, g)
		return g, nil
	}

	if explicitRoot != "" {
		rootAbs, err := filepath.Abs(explicitRoot)
		if err != nil {
			return nil, err
		}
		g, err := group(rootAbs)
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			g.targets = append(g.targets, "") // whole tree
			return order, nil
		}
		for _, p := range paths {
			argAbs := p
			if !filepath.IsAbs(p) {
				argAbs = filepath.Join(rootAbs, p)
			}
			rel, err := relTarget(rootAbs, argAbs)
			if err != nil {
				return nil, err
			}
			g.targets = append(g.targets, rel)
		}
		return order, nil
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("hydrate needs at least one <path> (or -C <syncdir> to hydrate a whole tree)")
	}
	for _, p := range paths {
		argAbs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		startDir := argAbs
		if fi, err := os.Stat(argAbs); err != nil || !fi.IsDir() {
			startDir = filepath.Dir(argAbs)
		}
		rootAbs, err := findSyncRoot(startDir)
		if err != nil {
			return nil, err
		}
		rel, err := relTarget(rootAbs, argAbs)
		if err != nil {
			return nil, err
		}
		g, err := group(rootAbs)
		if err != nil {
			return nil, err
		}
		g.targets = append(g.targets, rel)
	}
	return order, nil
}

// relTarget returns argAbs as a slash path relative to rootAbs, mapping the root
// itself to "" (meaning "everything"), and rejecting a path outside the root.
func relTarget(rootAbs, argAbs string) (string, error) {
	rel, err := filepath.Rel(rootAbs, argAbs)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the sync root %s", argAbs, rootAbs)
	}
	return filepath.ToSlash(rel), nil
}

// findSyncRoot ascends from start to the nearest directory holding a sync index.
func findSyncRoot(start string) (string, error) {
	dir := start
	for {
		if fi, err := os.Stat(filepath.Join(dir, syncIndexName)); err == nil && !fi.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no %s in %s or any parent directory (run `revika-ctl sync` first)", syncIndexName, start)
		}
		dir = parent
	}
}

// runHydrateGroup fetches the content of every index entry matched by the
// group's targets, updating the index in place and rewriting it. It returns how
// many files were hydrated.
func runHydrateGroup(ctx context.Context, s store.Store, g *hydrateGroup) (int, error) {
	matched := map[int]bool{}
	for _, t := range g.targets {
		hits := 0
		for i := range g.idx.Files {
			f := &g.idx.Files[i]
			if t == "" || f.Path == t || strings.HasPrefix(f.Path, t+"/") {
				matched[i] = true
				hits++
			}
		}
		if hits == 0 {
			label := t
			if label == "" {
				label = "."
			}
			fmt.Fprintf(os.Stderr, "warning: no synced files under %q\n", label)
		}
	}

	n := 0
	for i := range g.idx.Files {
		if !matched[i] {
			continue
		}
		f := &g.idx.Files[i]
		target := filepath.Join(g.root, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return n, err
		}
		if _, err := restoreFile(ctx, s, f.Cap, target); err != nil {
			return n, fmt.Errorf("hydrate %s: %w", f.Path, err)
		}
		f.Hydrated = true
		fmt.Fprintf(os.Stderr, "hydrated %s\n", f.Path)
		n++
	}
	if n > 0 {
		if err := writeSyncIndex(g.root, g.idx); err != nil {
			return n, fmt.Errorf("update sync index: %w", err)
		}
	}
	return n, nil
}

// safeEntryName rejects a directory entry name that could escape its parent
// directory when joined to a local path — an empty name, "."/"..", or one
// carrying a path separator. A directory blob is untrusted input (it may have
// been tampered with on a node), so every name is checked before it becomes a
// filesystem path.
func safeEntryName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("unsafe entry name %q", name)
	}
	return nil
}

// writeSyncIndex writes idx to <dir>/.revika-sync.json (0600 — it holds caps).
func writeSyncIndex(dir string, idx *syncIndex) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, syncIndexName), append(data, '\n'), 0o600)
}

// readSyncIndex loads the index a prior `sync` wrote under dir.
func readSyncIndex(dir string) (*syncIndex, error) {
	data, err := os.ReadFile(filepath.Join(dir, syncIndexName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no %s in %s (run `revika-ctl sync` first)", syncIndexName, dir)
		}
		return nil, err
	}
	var idx syncIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Join(dir, syncIndexName), err)
	}
	if idx.Version < 1 || idx.Version > syncIndexVersion {
		return nil, fmt.Errorf("unsupported sync index version %d (want 1..%d)", idx.Version, syncIndexVersion)
	}
	return &idx, nil
}
