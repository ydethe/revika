package manifest

import (
	"context"
	"path"
	"sort"
	"strings"

	"revika/internal/pipeline"
	"revika/internal/store"
)

// MergeLabeler names the conflict copy kept for a leaf that both sides edited
// differently: given the losing entry's name it returns the name its copy is
// filed under (e.g. "report.pdf" -> "report (conflict laptop-3f9a).pdf"). The
// caller injects a device-tagged labeler so two devices never collide on the
// copy name; DefaultLabeler is the untagged fallback.
type MergeLabeler func(name string) string

// DefaultLabeler files a conflict copy as "<stem> (conflict)<ext>". Callers that
// know their device tag should inject a labeler that embeds it so a copy is
// traceable to the device that produced it.
func DefaultLabeler(name string) string {
	ext := path.Ext(name)
	return strings.TrimSuffix(name, ext) + " (conflict)" + ext
}

// Merge3 three-way merges two divergent roots over the copy-on-write Merkle DAG.
// base is the last root the two lines shared (a zero cap means no common
// ancestor — everything reads as freshly added on both sides). local and remote
// are the two current roots to reconcile; the result is a single merged root cap
// plus the slash-paths that produced a conflict copy.
//
// It relies on content addressing: an unchanged subtree keeps an identical cap on
// both sides, so whole subtrees are pruned by cap equality without being loaded.
// Only where a directory genuinely diverges does Merge3 descend and merge entry
// by entry. A leaf both sides changed differently is never silently dropped — the
// local edit stays under its name and the remote edit is filed as a conflict copy
// via label; a delete on one side that races an edit on the other keeps the edit.
//
// The result is content-complete and structurally deterministic: given the same
// (base, local, remote, label) the same entries are selected at every level. It
// is not cap-identical across runs — a re-stored merged directory takes a fresh
// per-blob key (StoreDir mints one), so two devices merging concurrently need not
// compute the same cap. Convergence instead comes from the caller: each published
// root advances a monotonic Seq and folds in the other side's changes, so the
// device that reads the higher Seq adopts a root that already contains its own
// edits, and the fork closes in at most one further round.
func Merge3(ctx context.Context, s store.Store, cfg pipeline.Config, base, local, remote ReadCap, label MergeLabeler) (ReadCap, []string, error) {
	if label == nil {
		label = DefaultLabeler
	}
	return mergeDir(ctx, s, cfg, "", base, local, remote, label)
}

// capEqual reports whether two caps address the identical blob (same key and
// same content-addressed shards). Because per-blob keys are random per write,
// equal caps mean the very same stored blob — exactly the copy-on-write invariant
// Merge3 prunes on: a subtree untouched on one side keeps its parent's cap.
func capEqual(a, b ReadCap) bool {
	if a.Kind != b.Kind || a.Compressed != b.Compressed || a.K != b.K || a.M != b.M || a.Key != b.Key {
		return false
	}
	if len(a.Shards) != len(b.Shards) {
		return false
	}
	for i := range a.Shards {
		if a.Shards[i] != b.Shards[i] {
			return false
		}
	}
	return true
}

// capPresent reports whether c refers to a blob at all. A zero ReadCap (no
// shards) is Merge3's "absent" sentinel: an entry missing from a directory, or a
// missing base/child during recursion.
func capPresent(c ReadCap) bool { return len(c.Shards) > 0 }

// loadDirOpt loads the directory a cap points at, treating an absent cap or a
// non-directory (a file where a directory used to be, or vice versa) as an empty
// directory so callers can diff entry sets uniformly.
func loadDirOpt(ctx context.Context, s store.Store, c ReadCap) (DirManifest, error) {
	if !capPresent(c) || c.Kind != KindDir {
		return DirManifest{}, nil
	}
	return LoadDir(ctx, s, c)
}

// mergeDir merges one directory node. prefix is the slash-path of this node
// (empty at the root, otherwise ending in "/") used only to label conflicts. The
// three cap-equality shortcuts prune an unchanged subtree without loading it;
// only a genuinely divergent directory is descended into.
func mergeDir(ctx context.Context, s store.Store, cfg pipeline.Config, prefix string, base, local, remote ReadCap, label MergeLabeler) (ReadCap, []string, error) {
	switch {
	case capEqual(local, remote):
		return local, nil, nil // identical on both sides (including both absent)
	case capEqual(base, local):
		return remote, nil, nil // only remote changed this subtree (edit or delete)
	case capEqual(base, remote):
		return local, nil, nil // only local changed this subtree
	}

	// Genuine divergence: merge entry by entry. A non-directory or absent side
	// contributes no entries, so a dir<->file or edit<->delete at this node is
	// handled by the parent's per-entry logic, never here.
	bD, err := loadDirOpt(ctx, s, base)
	if err != nil {
		return ReadCap{}, nil, err
	}
	lD, err := loadDirOpt(ctx, s, local)
	if err != nil {
		return ReadCap{}, nil, err
	}
	rD, err := loadDirOpt(ctx, s, remote)
	if err != nil {
		return ReadCap{}, nil, err
	}

	bE := entryMap(bD)
	lE := entryMap(lD)
	rE := entryMap(rD)

	out := NewDir(lD.Meta)
	var conflicts []string

	for _, name := range unionNames(lE, rE) {
		le, lok := lE[name]
		re, rok := rE[name]
		be := bE[name] // zero Entry (absent cap) when not present
		lc, rc, bc := le.Cap, re.Cap, be.Cap

		switch {
		case capEqual(lc, rc):
			if lok { // identical on both sides; skip when both absent
				out = out.Upsert(le)
			}
		case capEqual(bc, lc):
			// local unchanged vs base ⇒ take remote's decision (edit or delete).
			if rok {
				out = out.Upsert(re)
			}
		case capEqual(bc, rc):
			// remote unchanged vs base ⇒ take local's decision.
			if lok {
				out = out.Upsert(le)
			}
		case !lok:
			// local deleted, remote edited ⇒ keep the edit, flag the conflict.
			out = out.Upsert(re)
			conflicts = append(conflicts, prefix+name)
		case !rok:
			// remote deleted, local edited ⇒ keep the edit, flag the conflict.
			out = out.Upsert(le)
			conflicts = append(conflicts, prefix+name)
		case lc.Kind == KindDir && rc.Kind == KindDir:
			// both edited a subdirectory ⇒ recurse and merge it.
			subCap, subConf, err := mergeDir(ctx, s, cfg, prefix+name+"/", bc, lc, rc, label)
			if err != nil {
				return ReadCap{}, nil, err
			}
			out = out.Upsert(Entry{Name: name, Cap: subCap, Stat: StatCache{Kind: KindDir}})
			conflicts = append(conflicts, subConf...)
		default:
			// both edited the same leaf differently (or a dir<->file swap): keep
			// local under its name and file remote as a conflict copy.
			out = out.Upsert(le)
			out = out.Upsert(Entry{Name: label(name), Cap: re.Cap, Stat: re.Stat})
			conflicts = append(conflicts, prefix+name)
		}
	}

	merged, err := StoreDir(ctx, s, cfg, out)
	if err != nil {
		return ReadCap{}, nil, err
	}
	return merged, conflicts, nil
}

// entryMap indexes a directory's entries by name for O(1) three-way lookup.
func entryMap(d DirManifest) map[string]Entry {
	m := make(map[string]Entry, len(d.Entries))
	for _, e := range d.Entries {
		m[e.Name] = e
	}
	return m
}

// unionNames returns the sorted union of the two entry sets' names, so the merge
// visits children in a fixed order and its output bytes are deterministic.
func unionNames(a, b map[string]Entry) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for name := range a {
		seen[name] = struct{}{}
	}
	for name := range b {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
