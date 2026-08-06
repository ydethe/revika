package manifest

import (
	"context"
	"fmt"
	"strings"

	"revika/internal/pipeline"
	"revika/internal/store"
)

// Rekey re-encrypts the subtree at subpath under fresh keys and grafts it back
// into a new root, returning the new root cap. It is the mechanism behind
// revocation (Architecture §3.5): a previously-shared cap names the *old* shard
// IDs, so once every blob at and below the shared subtree is re-encrypted to new
// content addresses, that cap can no longer locate the current bytes. The caller
// then advances the RootPointer to the returned cap and reclaims the orphaned old
// shards; anyone holding a stale cap keeps only bytes that are being garbage
// collected.
//
// It is copy-on-write: only the subtree and the directories on the path to it are
// rewritten (Graft), so sibling subtrees keep their caps and shards untouched.
// An empty subpath rekeys the whole namespace. Rekey needs read access — it
// decrypts and re-encrypts every blob — so a sign-key-only holder cannot perform
// it. Cost is O(subtree bytes): every data shard under the subtree is rewritten.
func Rekey(ctx context.Context, s store.Store, cfg pipeline.Config, root ReadCap, subpath string) (ReadCap, error) {
	parts, err := splitPath(subpath)
	if err != nil {
		return ReadCap{}, err
	}
	sub, err := Resolve(ctx, s, root, subpath)
	if err != nil {
		return ReadCap{}, fmt.Errorf("manifest: rekey resolve %q: %w", subpath, err)
	}
	newSub, err := rekeyTree(ctx, s, cfg, sub)
	if err != nil {
		return ReadCap{}, err
	}
	if len(parts) == 0 {
		return newSub, nil
	}
	// Preserve the parent's cached Stat for the leaf (size/mode are unchanged by a
	// rekey; only the content addresses move), then graft the fresh subtree back.
	parent, err := Resolve(ctx, s, root, strings.Join(parts[:len(parts)-1], "/"))
	if err != nil {
		return ReadCap{}, fmt.Errorf("manifest: rekey resolve parent of %q: %w", subpath, err)
	}
	pd, err := LoadDir(ctx, s, parent)
	if err != nil {
		return ReadCap{}, err
	}
	e, ok := pd.Lookup(parts[len(parts)-1])
	if !ok {
		return ReadCap{}, fmt.Errorf("manifest: rekey: %q not found in parent", subpath)
	}
	return Graft(ctx, s, cfg, root, subpath, newSub, e.Stat)
}

// rekeyTree re-encrypts the blob at c and, for a directory, every blob reachable
// below it, returning the cap of the freshly-encrypted subtree. Because
// StoreFileManifest and StoreDir mint a fresh per-blob key on every call, each
// manifest and directory blob gets a new cap for free; the file data chunks are
// re-encrypted explicitly via pipeline.ReencryptFile.
func rekeyTree(ctx context.Context, s store.Store, cfg pipeline.Config, c ReadCap) (ReadCap, error) {
	switch c.Kind {
	case KindFile:
		m, err := LoadFileManifest(ctx, s, c)
		if err != nil {
			return ReadCap{}, err
		}
		rm, err := pipeline.ReencryptFile(ctx, s, m)
		if err != nil {
			return ReadCap{}, err
		}
		return StoreFileManifest(ctx, s, cfg, rm)
	case KindDir:
		d, err := LoadDir(ctx, s, c)
		if err != nil {
			return ReadCap{}, err
		}
		out := DirManifest{Meta: d.Meta, Entries: make([]Entry, len(d.Entries))}
		for i, e := range d.Entries {
			child, err := rekeyTree(ctx, s, cfg, e.Cap)
			if err != nil {
				return ReadCap{}, fmt.Errorf("manifest: rekey %q: %w", e.Name, err)
			}
			out.Entries[i] = Entry{Name: e.Name, Cap: child, Stat: e.Stat}
		}
		return StoreDir(ctx, s, cfg, out)
	default:
		return ReadCap{}, fmt.Errorf("manifest: rekey: unknown cap kind %s", c.Kind)
	}
}
