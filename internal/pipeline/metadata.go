package pipeline

import (
	"crypto/sha256"
	"encoding/binary"
	"io/fs"
	"sort"
)

// Flag bits are the cross-platform, framework-neutral file attributes that both
// macOS File Provider (NSFileProviderItem) and Windows Cloud Filter
// (FILE_ATTRIBUTE_*) can express but that have no home in the POSIX Mode. They
// are stored separately so a Windows-origin attribute like "system" survives a
// round-trip even though no POSIX mode bit encodes it.
const (
	FlagHidden   = 1 << iota // dotfile on Unix; FILE_ATTRIBUTE_HIDDEN on Windows
	FlagReadOnly             // no write bits on Unix; FILE_ATTRIBUTE_READONLY on Windows
	FlagSystem               // FILE_ATTRIBUTE_SYSTEM (Windows); no Unix equivalent
	FlagArchive              // FILE_ATTRIBUTE_ARCHIVE (Windows); no Unix equivalent
)

// Metadata is the filesystem attribute set a FileManifest carries so a stored
// file round-trips back into a real filesystem, and so the native cloud-provider
// frameworks — macOS FileProvider.framework and Windows Cloud Filter (cldapi) —
// have every field they need to present the file as a placeholder without
// hydrating its content (Architecture §3.8). Name and Size live on FileManifest;
// everything else stat() exposes lives here.
//
// Field → framework mapping:
//
//	Mode           Go io/fs.FileMode bits (portable type+perm). File Provider
//	               fileSystemFlags (user r/w/x); Cloud Filter FILE_ATTRIBUTE_DIRECTORY/READONLY.
//	Uid, Gid       POSIX owner/group. File Provider ownerNameComponents (best effort);
//	               no Cloud Filter analogue.
//	ModTimeNS      POSIX mtime. File Provider contentModificationDate; Cloud Filter LastWriteTime.
//	ChangeTimeNS   POSIX ctime (inode change). Cloud Filter ChangeTime; no File Provider analogue.
//	AccessTimeNS   POSIX atime. File Provider lastUsedDate; Cloud Filter LastAccessTime.
//	BirthTimeNS    creation/birth time. File Provider creationDate; Cloud Filter CreationTime.
//	Flags          cross-platform attribute bits (see Flag*). File Provider
//	               fileSystemFlags; Cloud Filter FILE_ATTRIBUTE_*.
//	ContentType    IANA MIME type. File Provider typeIdentifier (UTType, derivable); advisory.
//	SymlinkTarget  non-empty iff a symlink. File Provider symlinkTargetPath; POSIX readlink.
//	Xattr          extended attributes. File Provider extendedAttributes; roughly
//	               Cloud Filter alternate data streams.
//	ContentVersion / MetaVersion  opaque change tokens matching File Provider's
//	               NSFileProviderItemVersion (contentVersion + metadataVersion);
//	               Cloud Filter uses them to detect drift. DeriveVersions computes
//	               them deterministically from the manifest.
//
// The stable item identifier (File Provider itemIdentifier / Cloud Filter
// FileIdentity) is deliberately NOT here: it is a namespace concern owned by the
// directory manifest (Architecture §3.6/§3.8), not a property of a file's content.
//
// All times are Unix nanoseconds; a zero time means "not captured on this
// platform" (see revika-ctl's per-OS capture) and is skipped on restore.
type Metadata struct {
	Mode           uint32
	Uid, Gid       uint32
	ModTimeNS      int64
	ChangeTimeNS   int64
	AccessTimeNS   int64
	BirthTimeNS    int64
	Flags          uint32
	ContentType    string
	SymlinkTarget  string
	Xattr          map[string][]byte
	ContentVersion []byte
	MetaVersion    []byte
}

// IsSymlink reports whether the manifest describes a symbolic link, whose target
// path is carried in SymlinkTarget rather than in the stored shard content.
func (m Metadata) IsSymlink() bool {
	return m.SymlinkTarget != "" || fs.FileMode(m.Mode)&fs.ModeSymlink != 0
}

// DeriveVersions fills m.Meta.ContentVersion and m.Meta.MetaVersion with
// deterministic change tokens: ContentVersion hashes the ordered shard IDs, so it
// changes exactly when the file's bytes change; MetaVersion hashes the attribute
// fields, so it changes exactly when an attribute changes. Together they are what
// a native cloud provider needs for NSFileProviderItemVersion (macOS) and for
// Cloud Filter drift detection (Windows) — a reader can tell "same content, new
// name" from "new content" without downloading a shard.
func DeriveVersions(m *FileManifest) {
	ch := sha256.New()
	for _, c := range m.Chunks {
		for _, id := range c.Shards {
			ch.Write(id[:])
		}
	}
	m.Meta.ContentVersion = ch.Sum(nil)[:16]

	mh := sha256.New()
	var u [8]byte
	putU32 := func(v uint32) { binary.LittleEndian.PutUint32(u[:4], v); mh.Write(u[:4]) }
	putI64 := func(v int64) { binary.LittleEndian.PutUint64(u[:], uint64(v)); mh.Write(u[:]) }
	putU32(m.Meta.Mode)
	putU32(m.Meta.Uid)
	putU32(m.Meta.Gid)
	putI64(m.Meta.ModTimeNS)
	putI64(m.Meta.ChangeTimeNS)
	putI64(m.Meta.AccessTimeNS)
	putI64(m.Meta.BirthTimeNS)
	putU32(m.Meta.Flags)
	mh.Write([]byte(m.Meta.ContentType))
	mh.Write([]byte{0})
	mh.Write([]byte(m.Meta.SymlinkTarget))
	mh.Write([]byte{0})
	for _, k := range sortedKeys(m.Meta.Xattr) {
		mh.Write([]byte(k))
		mh.Write([]byte{0})
		mh.Write(m.Meta.Xattr[k])
	}
	m.Meta.MetaVersion = mh.Sum(nil)[:16]
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
