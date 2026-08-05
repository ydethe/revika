package sync

import (
	"context"
	"fmt"

	"revika/internal/provider"
)

// remoteState is one entry of a scan of the stored namespace: the stable item
// ID, its classification, and the version tokens that make "changed remotely" a
// cheap comparison rather than a re-download. Symlink targets and the full
// attribute record are fetched lazily at apply time (via provider.Stat), so a
// scan touches only directory blobs.
type remoteState struct {
	id        provider.ItemID
	kind      kind
	isSymlink bool
	size      int64
	content   []byte // provider.ItemVersion.Content — changes iff the bytes change
	meta      []byte // provider.ItemVersion.Meta    — changes iff an attribute changes
}

// remoteSnapshot maps a slash-relative path (from the root container) to its
// state.
type remoteSnapshot map[string]remoteState

// scanRemote enumerates the whole stored tree beneath the provider root and
// returns the state of every item, keyed by slash-relative path. It reads only
// directory blobs (Enumerate), never file content — the placeholder-cheap walk
// of Architecture §3.8.
func scanRemote(ctx context.Context, prov provider.Provider) (remoteSnapshot, error) {
	root, err := prov.Root(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync: remote root: %w", err)
	}
	snap := remoteSnapshot{}
	if err := scanRemoteDir(ctx, prov, root, "", snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// scanRemoteDir lists dir (whose slash path within the root is prefix) and
// recurses into subdirectories, filling snap.
func scanRemoteDir(ctx context.Context, prov provider.Provider, dir provider.ItemID, prefix string, snap remoteSnapshot) error {
	items, err := prov.Enumerate(ctx, dir)
	if err != nil {
		return fmt.Errorf("sync: enumerate %q: %w", prefix, err)
	}
	for _, it := range items {
		rel := it.Name
		if prefix != "" {
			rel = prefix + "/" + it.Name
		}
		snap[rel] = remoteState{
			id:        it.ID,
			kind:      itemKindOf(it),
			isSymlink: it.IsLink,
			size:      it.Size,
			content:   it.Version.Content,
			meta:      it.Version.Meta,
		}
		if it.IsDir {
			if err := scanRemoteDir(ctx, prov, it.ID, rel, snap); err != nil {
				return err
			}
		}
	}
	return nil
}
