package provider

import (
	"strconv"
	"strings"
	"sync"
)

// identity is the provider's authoritative path⇄ItemID map. The native
// frameworks require an identifier that stays stable across renames and moves
// (see the package doc); a slash path does not, so the provider — the sole
// mutator of its domain — mints an opaque ID for each path the first time it is
// seen and re-keys the map on rename/move/delete. Paths are slash-separated and
// root-relative; the empty string is the root, bound to RootID.
//
// Concurrency: every method locks, so the map stays consistent under the
// interface's concurrent-use guarantee.
type identity struct {
	mu     sync.Mutex
	byID   map[ItemID]string
	byPath map[string]ItemID
	next   uint64
}

func newIdentity() *identity {
	i := &identity{
		byID:   map[ItemID]string{RootID: ""},
		byPath: map[string]ItemID{"": RootID},
	}
	return i
}

// idFor returns the stable ID for a path, minting one on first sight. Repeated
// calls for the same path (until it is renamed or removed) return the same ID.
func (i *identity) idFor(path string) ItemID {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.idForLocked(path)
}

func (i *identity) idForLocked(path string) ItemID {
	if id, ok := i.byPath[path]; ok {
		return id
	}
	i.next++
	id := ItemID("i" + strconv.FormatUint(i.next, 10))
	i.byPath[path] = id
	i.byID[id] = path
	return id
}

// pathFor returns the path an ID currently maps to.
func (i *identity) pathFor(id ItemID) (string, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	p, ok := i.byID[id]
	return p, ok
}

// rename re-keys oldPath (and, if it is a directory, every descendant path) to
// newPath, preserving the IDs so identifiers survive the move. Any ID that was
// bound under the old prefix now resolves to its new location.
func (i *identity) rename(oldPath, newPath string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for p, id := range collectSubtree(i.byPath, oldPath) {
		suffix := strings.TrimPrefix(p, oldPath)
		np := newPath + suffix
		delete(i.byPath, p)
		i.byPath[np] = id
		i.byID[id] = np
	}
}

// remove drops path and, for a directory, all descendant paths from both maps,
// so their IDs are retired (a later recreation gets a fresh ID — a new item).
func (i *identity) remove(path string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for p, id := range collectSubtree(i.byPath, path) {
		delete(i.byPath, p)
		delete(i.byID, id)
	}
}

// collectSubtree returns the entries of byPath at prefix or below it (prefix
// itself and any path starting with prefix+"/"). Returning a snapshot lets the
// caller mutate the maps while iterating.
func collectSubtree(byPath map[string]ItemID, prefix string) map[string]ItemID {
	out := map[string]ItemID{}
	for p, id := range byPath {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			out[p] = id
		}
	}
	return out
}
