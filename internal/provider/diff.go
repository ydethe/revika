package provider

import (
	"context"

	"revika/internal/manifest"
)

// diff walks two root caps and returns the deltas between them, exactly as the
// frameworks' change enumeration wants (added / modified / deleted). Because the
// tree is a Merkle DAG of content-addressed blobs, two equal caps address an
// identical subtree, so cap equality prunes whole unchanged branches without
// reading them — the diff cost is proportional to what actually changed, not to
// the size of the namespace.
//
// oldRoot may be the zero cap (a caller syncing from empty), in which case every
// current item surfaces as ChangeAdded.
func (p *Manifest) diff(ctx context.Context, oldRoot, newRoot manifest.ReadCap) ([]Change, error) {
	var changes []Change
	if err := p.diffDir(ctx, "", oldRoot, newRoot, &changes); err != nil {
		return nil, err
	}
	return changes, nil
}

// diffDir compares the directory at path between the old and new trees, appending
// deltas for its subtree. Either cap may be zero / non-directory, treated as an
// empty directory (so a whole side being absent yields pure adds or deletes).
func (p *Manifest) diffDir(ctx context.Context, path string, oldCap, newCap manifest.ReadCap, out *[]Change) error {
	if capEqual(oldCap, newCap) {
		return nil // identical subtree — prune
	}
	oldEntries, err := p.dirEntries(ctx, oldCap)
	if err != nil {
		return err
	}
	newEntries, err := p.dirEntries(ctx, newCap)
	if err != nil {
		return err
	}

	for name, ne := range newEntries {
		childPath := join(path, name)
		oe, existed := oldEntries[name]
		switch {
		case !existed:
			// New name: the whole subtree is added.
			if err := p.emitSubtree(ctx, path, name, ne, ChangeAdded, out); err != nil {
				return err
			}
		case capEqual(oe.Cap, ne.Cap):
			// Unchanged — skip.
		case oe.Cap.Kind == manifest.KindDir && ne.Cap.Kind == manifest.KindDir:
			// Both directories changed: recurse to find the specific deltas.
			if err := p.diffDir(ctx, childPath, oe.Cap, ne.Cap, out); err != nil {
				return err
			}
		default:
			// File edited, or the name changed kind (file↔dir): a modification.
			it := p.itemFromEntry(path, ne)
			*out = append(*out, Change{Type: ChangeModified, ID: it.ID, Path: childPath, Item: &it})
		}
	}

	for name, oe := range oldEntries {
		if _, stillThere := newEntries[name]; stillThere {
			continue
		}
		if err := p.emitSubtree(ctx, path, name, oe, ChangeDeleted, out); err != nil {
			return err
		}
	}
	return nil
}

// emitSubtree appends a change of kind t for the entry (name under parentPath)
// and, when it is a directory, for every descendant — so an added or deleted
// directory reports each item it brought or took with it, as the frameworks
// expect. Deleted changes carry only the ID (Item is nil).
func (p *Manifest) emitSubtree(ctx context.Context, parentPath, name string, e manifest.Entry, t ChangeType, out *[]Change) error {
	childPath := join(parentPath, name)
	if t == ChangeDeleted {
		*out = append(*out, Change{Type: t, ID: p.ids.idFor(childPath), Path: childPath})
	} else {
		it := p.itemFromEntry(parentPath, e)
		*out = append(*out, Change{Type: t, ID: it.ID, Path: childPath, Item: &it})
	}
	if e.Cap.Kind != manifest.KindDir {
		return nil
	}
	entries, err := p.dirEntries(ctx, e.Cap)
	if err != nil {
		return err
	}
	for cn, ce := range entries {
		if err := p.emitSubtree(ctx, childPath, cn, ce, t, out); err != nil {
			return err
		}
	}
	return nil
}

// dirEntries loads a directory cap into a name→entry map. A zero cap or a
// non-directory cap yields an empty map, so callers can treat an absent side as
// an empty directory.
func (p *Manifest) dirEntries(ctx context.Context, c manifest.ReadCap) (map[string]manifest.Entry, error) {
	if c.Kind != manifest.KindDir {
		return map[string]manifest.Entry{}, nil
	}
	d, err := manifest.LoadDir(ctx, p.store, c)
	if err != nil {
		return nil, err
	}
	m := make(map[string]manifest.Entry, len(d.Entries))
	for _, e := range d.Entries {
		m[e.Name] = e
	}
	return m, nil
}
