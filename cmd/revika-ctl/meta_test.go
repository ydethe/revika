package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"revika/internal/fsmeta"
	"revika/internal/pipeline"
)

// Capture/Restore round-tripping against the real filesystem is covered by
// internal/fsmeta; this file keeps the client-specific manifest-serialization
// and symlink-through-runStore tests.

// TestManifestMetadataRoundTrip checks every metadata field survives JSON
// encode/decode, including the byte-valued xattrs and version tokens.
func TestManifestMetadataRoundTrip(t *testing.T) {
	orig := pipeline.FileManifest{
		Name:   "doc.pdf",
		Params: pipeline.DefaultConfig(),
		Size:   99,
		Meta: pipeline.Metadata{
			Mode:           0o644,
			Uid:            1000,
			Gid:            1001,
			ModTimeNS:      111,
			ChangeTimeNS:   222,
			AccessTimeNS:   333,
			BirthTimeNS:    444,
			Flags:          pipeline.FlagHidden | pipeline.FlagReadOnly,
			ContentType:    "application/pdf",
			Xattr:          map[string][]byte{"user.comment": []byte("hi\x00there")},
			ContentVersion: []byte{1, 2, 3, 4},
			MetaVersion:    []byte{5, 6, 7, 8},
		},
	}
	data, err := encodeManifest(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeManifest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	g, w := got.Meta, orig.Meta
	if g.Mode != w.Mode || g.Uid != w.Uid || g.Gid != w.Gid ||
		g.ModTimeNS != w.ModTimeNS || g.ChangeTimeNS != w.ChangeTimeNS ||
		g.AccessTimeNS != w.AccessTimeNS || g.BirthTimeNS != w.BirthTimeNS ||
		g.Flags != w.Flags || g.ContentType != w.ContentType {
		t.Fatalf("scalar metadata mismatch:\n got %+v\nwant %+v", g, w)
	}
	if string(g.Xattr["user.comment"]) != string(w.Xattr["user.comment"]) {
		t.Errorf("xattr mismatch: %q", g.Xattr["user.comment"])
	}
	if string(g.ContentVersion) != string(w.ContentVersion) || string(g.MetaVersion) != string(w.MetaVersion) {
		t.Error("version token mismatch")
	}
}

// TestDecodeLegacyManifestNoMeta checks a pre-v4 manifest (no metadata object)
// still decodes, with a zero Metadata.
func TestDecodeLegacyManifestNoMeta(t *testing.T) {
	v3 := `{"version":3,"name":"old.bin","chunk_size":4,"k":4,"m":2,"size":10,` +
		`"chunks":[{"key":"` + hexKey() + `","shards":[]}]}`
	m, err := decodeManifest([]byte(v3))
	if err != nil {
		t.Fatalf("decode v3: %v", err)
	}
	if m.Name != "old.bin" {
		t.Errorf("name = %q", m.Name)
	}
	if !metaIsZero(m.Meta) {
		t.Errorf("expected zero metadata, got %+v", m.Meta)
	}
}

func metaIsZero(m pipeline.Metadata) bool {
	return m.Mode == 0 && m.ModTimeNS == 0 && m.ContentType == "" &&
		m.SymlinkTarget == "" && len(m.Xattr) == 0 && len(m.ContentVersion) == 0
}

// hexKey returns a valid 32-byte hex key for the legacy manifest fixture.
func hexKey() string {
	s := ""
	for range 32 {
		s += "00"
	}
	return s
}

// TestSymlinkStoreRestore stores a symlink through runStore and recreates it via
// restoreSymlink, proving symlinks round-trip as metadata rather than content.
func TestSymlinkStoreRestore(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/etc/hostname", link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	m, err := runStore(ctx, s, pipeline.DefaultConfig(), link)
	if err != nil {
		t.Fatalf("runStore: %v", err)
	}
	if !m.Meta.IsSymlink() || m.Meta.SymlinkTarget != "/etc/hostname" {
		t.Fatalf("symlink not captured: %+v", m.Meta)
	}

	out := filepath.Join(dir, "restored")
	if err := fsmeta.RestoreSymlink(out, m.Meta); err != nil {
		t.Fatalf("RestoreSymlink: %v", err)
	}
	tgt, err := os.Readlink(out)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if tgt != "/etc/hostname" {
		t.Errorf("restored target = %q", tgt)
	}
}
