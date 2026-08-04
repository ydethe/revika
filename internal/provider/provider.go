// Package provider is revika's OS filesystem-integration API: the
// framework-neutral surface a native "cloud provider" extension drives to
// present revika as an on-demand filesystem (Architecture §3.8). It is the union
// of the operations the three native frameworks require, expressed once in Go so
// a single core serves all of them:
//
//   - macOS  — FileProvider.framework (NSFileProviderReplicatedExtension)
//   - Windows — Cloud Filter API (cldapi.dll / Sync Root, "Files On-Demand")
//   - Linux  — GVfs / GIO (and FUSE via internal/mount as the cross-platform PoC)
//
// Each framework speaks a different dialect, but the shape is the same: a stable
// item identity, a content/metadata version pair, container enumeration with a
// delta cursor, on-demand content fetch (hydration) and eviction (dehydration),
// and create/modify/delete/rename mutations. Provider is that shape. A per-OS
// binding layer (not pure Go — a cgo/Swift/C# shim, deferred per Architecture
// §3.8) translates the native callbacks into these method calls; nothing here
// touches an OS API, so it builds and tests on every platform.
//
// # Mapping to the native callbacks
//
//	Provider method        macOS File Provider              Windows Cloud Filter            Linux GVfs/VFS
//	-----------------      ------------------------------   -----------------------------   -----------------
//	Root                   .rootContainer identifier        Sync Root registration          mount root
//	Stat                   item(for:)                       CF_CALLBACK getattr/basic info  query_info
//	Lookup                 (enumerator match)               FETCH_PLACEHOLDERS (one)        lookup
//	Enumerate              enumerateItems(for:)             CF FETCH_PLACEHOLDERS           enumerate
//	EnumerateChanges       enumerateChanges(from:)          in-sync/drift reconcile         (poll + diff)
//	CurrentAnchor          currentSyncAnchor                USN cursor                      (etag)
//	FetchContents          fetchContents(for:)              CF_CALLBACK_TYPE_FETCH_DATA     open + read
//	Evict                  evictItem(identifier:)           CfUpdatePlaceholder(DEHYDRATE)  drop cache
//	CreateItem             createItem(basedOn:)             upload + CfCreatePlaceholders   create / mkdir
//	ModifyItem             modifyItem(_:changedFields:)     sync-out changed data           write / setattr
//	DeleteItem             deleteItem(identifier:)          delete sync                     delete / rmdir
//	Rename                 modifyItem (parent/filename)     rename sync                     move / set_name
//
// # What backs it
//
// The default implementation, Manifest (manifest.go), resolves every call
// against revika's cap-addressed Merkle DAG (internal/manifest) over any
// store.Store: enumeration reads directory blobs, fetch runs pipeline.LoadFile,
// and each mutation is a copy-on-write Graft that advances a signed RootPointer
// (Architecture §4). The one piece not yet networked — publishing that pointer
// over the DHT — is isolated behind the RootStore seam, so the API is complete
// today and only its persistence backend changes when DHT root publication lands.
//
// # Item identity
//
// The frameworks require an identifier that is STABLE across renames and moves
// (File Provider itemIdentifier / Cloud Filter FileIdentity). revika's content
// caps are not that (a file's cap is stable across rename but changes on every
// edit), so identity is owned here: the provider is the sole mutator of its
// domain, so it maintains the path⇄ID mapping and re-keys it on Rename/Delete
// (identity.go). A future manifest Entry.ID field (Architecture §3.6) could make
// identity intrinsic to the DAG; until then this index is authoritative.
package provider

import (
	"context"
	"io"

	"revika/internal/manifest"
	"revika/internal/pipeline"
)

// ItemID is the stable, opaque identifier the native frameworks address an item
// by (File Provider NSFileProviderItemIdentifier, Cloud Filter FileIdentity). It
// survives renames and moves; it is minted and tracked by the provider, not
// derived from the item's path or content, so a caller must treat it as opaque.
type ItemID string

// RootID identifies the root container — the mount point. It maps to File
// Provider's NSFileProviderRootContainerItemIdentifier and to a Cloud Filter
// Sync Root. Enumeration and creation start from here.
const RootID ItemID = "root"

// ItemVersion is the change token pair every framework uses to tell "same
// content, new name" from "new content" without downloading a shard: File
// Provider's NSFileProviderItemVersion (contentVersion + metadataVersion) and
// Cloud Filter's drift detection. Content changes iff the bytes change; Meta
// changes iff an attribute changes. Both are opaque bytes (derived from the
// manifest by pipeline.DeriveVersions for files, from the blob cap for dirs).
type ItemVersion struct {
	Content []byte
	Meta    []byte
}

// Capabilities is the per-item permission bitset a framework shows and enforces
// (File Provider NSFileProviderItemCapabilities; Cloud Filter attribute flags).
type Capabilities uint32

const (
	CapRead        Capabilities = 1 << iota // fetch/read content
	CapWrite                                 // modify content
	CapRename                                // change name in place
	CapReparent                              // move to a different parent
	CapDelete                                // remove
	CapAddSubItems                           // create children (directories only)
	CapEnumerate                             // list children (directories only)
)

// Has reports whether the bitset includes capability c.
func (caps Capabilities) Has(c Capabilities) bool { return caps&c != 0 }

// Item is a placeholder-ready description of one filesystem object: everything a
// framework needs to present it WITHOUT hydrating its content. It maps to a File
// Provider NSFileProviderItem and to the fields of a Cloud Filter placeholder
// (CF_PLACEHOLDER_CREATE_INFO + FILE_BASIC_INFO).
//
// Meta carries the POSIX/cross-platform attributes (mode, owner, the four times,
// flags, symlink target, xattrs; see pipeline.Metadata). From Enumerate, Meta is
// the light subset a parent directory caches (mode + mtime) so a listing is
// cheap; Stat returns the full record by reading the item's own blob. Cap is the
// underlying read-capability, exposed so a caller can fetch or share the item.
type Item struct {
	ID      ItemID
	Parent  ItemID
	Name    string
	IsDir   bool
	IsLink  bool
	Size    int64
	Version ItemVersion
	Meta    pipeline.Metadata
	Caps    Capabilities
	Cap     manifest.ReadCap
}

// CreateRequest describes a new item for CreateItem. Contents is read to
// completion for a regular file and ignored for a directory (IsDir) or a symlink
// (Meta.SymlinkTarget set). Meta supplies the attributes to record.
type CreateRequest struct {
	Name     string
	IsDir    bool
	Meta     pipeline.Metadata
	Contents io.Reader
}

// ModifyRequest describes an in-place change for ModifyItem: new content and/or
// new attributes. A nil Contents leaves the bytes untouched (a metadata-only
// change — new MetaVersion, same ContentVersion); a nil Meta leaves attributes
// untouched. Renames and moves go through Rename, not here, mirroring how the
// frameworks separate content/attribute edits from namespace edits.
type ModifyRequest struct {
	Contents io.Reader
	Meta     *pipeline.Metadata
}

// ChangeType tags a delta returned by EnumerateChanges.
type ChangeType int

const (
	ChangeAdded    ChangeType = iota // item newly present since the anchor
	ChangeModified                   // content or metadata changed
	ChangeDeleted                    // item removed since the anchor
)

// Change is one delta in a ChangeSet: the item that changed and how. Item is nil
// for ChangeDeleted (only the ID is meaningful then). Path is the item's current
// slash path, provided for logging and for a binding layer that maps IDs to
// native placeholders.
type Change struct {
	Type ChangeType
	ID   ItemID
	Path string
	Item *Item
}

// ChangeSet is the result of EnumerateChanges: the deltas since the caller's
// anchor and a fresh anchor to pass next time. It maps to File Provider's
// enumerateChanges(from:) result (updated/deleted + a new sync anchor).
type ChangeSet struct {
	Changes []Change
	Anchor  SyncAnchor
}

// Provider is the framework-neutral filesystem-integration API. A per-OS binding
// layer drives it from the native cloud-provider callbacks (see the package doc
// for the mapping). All methods are safe for concurrent use.
type Provider interface {
	// Root returns the root container identifier (the mount point).
	Root(ctx context.Context) (ItemID, error)

	// Stat returns the full description of one item, reading its own blob so
	// Meta is complete. VFS getattr / File Provider item(for:).
	Stat(ctx context.Context, id ItemID) (Item, error)

	// Lookup resolves a child by name within a directory. VFS lookup.
	Lookup(ctx context.Context, parent ItemID, name string) (Item, error)

	// Enumerate lists the direct children of a directory as placeholder-ready
	// Items, touching no file content. File Provider enumerateItems(for:),
	// Cloud Filter FETCH_PLACEHOLDERS, VFS readdir.
	Enumerate(ctx context.Context, dir ItemID) ([]Item, error)

	// CurrentAnchor returns the cursor naming the domain's current state, to be
	// handed back to EnumerateChanges later. File Provider currentSyncAnchor.
	CurrentAnchor(ctx context.Context) (SyncAnchor, error)

	// EnumerateChanges returns every item added, modified, or deleted since the
	// given anchor, plus a fresh anchor. It diffs the Merkle DAG, so unchanged
	// subtrees are pruned by cap equality. File Provider enumerateChanges(from:).
	EnumerateChanges(ctx context.Context, since SyncAnchor) (ChangeSet, error)

	// FetchContents streams an item's bytes to w (on-demand hydration) and
	// returns the version it served, so the caller can stamp the materialized
	// file. File Provider fetchContents, Cloud Filter FETCH_DATA, VFS open+read.
	FetchContents(ctx context.Context, id ItemID, w io.Writer) (ItemVersion, error)

	// Evict signals that an item's local content may be dropped to reclaim space
	// (dehydration). Because revika content is remote by nature, the manifest
	// backing keeps no local copy and this is a no-op there; a mount with a
	// placeholder cache overrides it. File Provider evictItem, Cloud Filter
	// CfUpdatePlaceholder(DEHYDRATE).
	Evict(ctx context.Context, id ItemID) error

	// CreateItem creates a file, directory, or symlink under parent and returns
	// its Item. File Provider createItem, Cloud Filter placeholder upload.
	CreateItem(ctx context.Context, parent ItemID, req CreateRequest) (Item, error)

	// ModifyItem replaces content and/or attributes of an existing item in
	// place. File Provider modifyItem, Cloud Filter sync-out.
	ModifyItem(ctx context.Context, id ItemID, req ModifyRequest) (Item, error)

	// DeleteItem removes an item (and, for a directory, its whole subtree).
	// File Provider deleteItem, VFS unlink/rmdir.
	DeleteItem(ctx context.Context, id ItemID) error

	// Rename moves and/or renames an item, keeping its ID stable. Pass the same
	// parent to rename in place, a different parent to reparent. File Provider
	// modifyItem(parentItemIdentifier/filename), VFS rename.
	Rename(ctx context.Context, id ItemID, newParent ItemID, newName string) (Item, error)
}

// Ensure Manifest satisfies the interface.
var _ Provider = (*Manifest)(nil)
