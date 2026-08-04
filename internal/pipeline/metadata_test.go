package pipeline

import (
	"bytes"
	"testing"

	"revika/internal/store"
)

func sid(b byte) store.ShardID {
	var id store.ShardID
	for i := range id {
		id[i] = b
	}
	return id
}

// TestDeriveVersionsDeterministic checks the version tokens are reproducible and
// non-empty for a given manifest — a reader must get the same token for the same
// content/metadata (File Provider NSFileProviderItemVersion, §3.8).
func TestDeriveVersionsDeterministic(t *testing.T) {
	m := FileManifest{
		Chunks: []ChunkRef{{Shards: []store.ShardID{sid(1), sid(2)}}},
		Meta:   Metadata{Mode: 0o644, ModTimeNS: 123},
	}
	a := m
	b := m
	DeriveVersions(&a)
	DeriveVersions(&b)
	if len(a.Meta.ContentVersion) == 0 || len(a.Meta.MetaVersion) == 0 {
		t.Fatal("version tokens must be non-empty")
	}
	if !bytes.Equal(a.Meta.ContentVersion, b.Meta.ContentVersion) || !bytes.Equal(a.Meta.MetaVersion, b.Meta.MetaVersion) {
		t.Fatal("DeriveVersions is not deterministic")
	}
}

// TestDeriveVersionsSeparatesContentAndMetadata is the property the sync
// frameworks rely on: changing only the bytes bumps ContentVersion but not
// MetaVersion, and changing only an attribute bumps MetaVersion but not
// ContentVersion.
func TestDeriveVersionsSeparatesContentAndMetadata(t *testing.T) {
	base := FileManifest{
		Chunks: []ChunkRef{{Shards: []store.ShardID{sid(1)}}},
		Meta:   Metadata{Mode: 0o644, ModTimeNS: 100},
	}
	DeriveVersions(&base)

	// Same bytes, different attribute (mtime): content stable, meta changes.
	metaChanged := base
	metaChanged.Meta.ModTimeNS = 200
	DeriveVersions(&metaChanged)
	if !bytes.Equal(metaChanged.Meta.ContentVersion, base.Meta.ContentVersion) {
		t.Error("ContentVersion changed for an attribute-only edit")
	}
	if bytes.Equal(metaChanged.Meta.MetaVersion, base.Meta.MetaVersion) {
		t.Error("MetaVersion did not change for an attribute edit")
	}

	// Different bytes (shard set), same attributes: content changes.
	bytesChanged := base
	bytesChanged.Chunks = []ChunkRef{{Shards: []store.ShardID{sid(9)}}}
	DeriveVersions(&bytesChanged)
	if bytes.Equal(bytesChanged.Meta.ContentVersion, base.Meta.ContentVersion) {
		t.Error("ContentVersion did not change for a content edit")
	}
}

func TestIsSymlink(t *testing.T) {
	if (Metadata{}).IsSymlink() {
		t.Error("empty metadata is not a symlink")
	}
	if !(Metadata{SymlinkTarget: "/etc/hosts"}).IsSymlink() {
		t.Error("a target makes it a symlink")
	}
}
