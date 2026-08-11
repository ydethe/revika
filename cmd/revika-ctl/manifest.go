package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"revika/internal/crypto"
	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// Decode-time allocation caps. A manifest is the user's own read-cap, but an
// accidentally or intentionally oversized array forces a large allocation
// before any shard is verified, which can exhaust memory. These limits are
// generous enough to never constrain legitimate files.
const (
	maxManifestChunks        = 1 << 20  // 1 M chunks → ~4 TiB at 4 MiB each
	maxManifestShardsPerChunk = 256     // well above any real k+m
)

// manifestVersion tags the on-disk format so a future reader can detect and
// migrate older files. v4 added filesystem metadata (mode/uid/gid/times/flags/
// content-type/symlink/xattr + version tokens) for native cloud-provider
// compatibility; v3 added compression flags; v2 added the original file name; v1
// manifests (no name) still decode. Older manifests predate these fields, so
// their absence decodes to the zero value (uncompressed, no metadata).
//
// Defence controls (security/Defence.md; primitive P19 in security/frameworks.md):
//
//	SI-7 (Software, Firmware, and Information Integrity) — partial: the version tag detects
//	     rollback/format downgrade; manifest integrity and secrecy otherwise rest on the encrypted
//	     cap wrap (internal/cap) and per-shard content hashes, not a standalone manifest signature.
const manifestVersion = 4

// jsonManifest is the serialized form of a pipeline.FileManifest. It IS the
// file's read-capability: the per-chunk keys plus the ordered shard content
// addresses are everything needed to fetch and decrypt the file. Anyone who
// holds this JSON can read the file, so it is treated as secret (and is what
// `share` wraps to a recipient's key).
//
// Serialization lives here in the client for now; when internal/manifest lands
// (encrypted, immutable, cap-addressed) it supersedes this.
type jsonManifest struct {
	Version   int         `json:"version"`
	Name      string      `json:"name,omitempty"` // original file name (v2+); may be empty
	ChunkSize int         `json:"chunk_size"`
	K         int         `json:"k"`
	M         int         `json:"m"`
	Compress  bool        `json:"compress,omitempty"` // compression was enabled (v3+)
	Size      int64       `json:"size"`
	Meta      *jsonMeta   `json:"meta,omitempty"` // filesystem metadata (v4+)
	Chunks    []jsonChunk `json:"chunks"`
}

// jsonMeta is the serialized form of pipeline.Metadata. Every field is
// omitempty so a partially-captured manifest (a platform that could not read,
// say, xattrs or birth time) stays compact, and an absent field decodes to the
// zero value. Times are Unix nanoseconds; xattr values and the version tokens
// are base64 / hex encoded because JSON has no byte-string type.
type jsonMeta struct {
	Mode           uint32            `json:"mode,omitempty"` // Go io/fs.FileMode bits
	Uid            uint32            `json:"uid,omitempty"`
	Gid            uint32            `json:"gid,omitempty"`
	ModTimeNS      int64             `json:"mtime_ns,omitempty"`
	ChangeTimeNS   int64             `json:"ctime_ns,omitempty"`
	AccessTimeNS   int64             `json:"atime_ns,omitempty"`
	BirthTimeNS    int64             `json:"btime_ns,omitempty"`
	Flags          uint32            `json:"flags,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	SymlinkTarget  string            `json:"symlink_target,omitempty"`
	Xattr          map[string]string `json:"xattr,omitempty"`           // values base64
	ContentVersion string            `json:"content_version,omitempty"` // hex
	MetaVersion    string            `json:"meta_version,omitempty"`    // hex
}

type jsonChunk struct {
	Key        string   `json:"key"`                  // hex of the 32-byte per-chunk AES key
	Compressed bool     `json:"compressed,omitempty"` // plaintext was DEFLATEd before encryption (v3+)
	Shards     []string `json:"shards"`               // hex of each 32-byte shard content address
}

// encodeManifest renders m as indented JSON.
func encodeManifest(m pipeline.FileManifest) ([]byte, error) {
	jm := jsonManifest{
		Version:   manifestVersion,
		Name:      m.Name,
		ChunkSize: m.Params.ChunkSize,
		K:         m.Params.Params.K,
		M:         m.Params.Params.M,
		Compress:  m.Params.Compress,
		Size:      m.Size,
		Meta:      encodeMeta(m.Meta),
		Chunks:    make([]jsonChunk, len(m.Chunks)),
	}
	for i, ch := range m.Chunks {
		shards := make([]string, len(ch.Shards))
		for j, id := range ch.Shards {
			shards[j] = id.String()
		}
		jm.Chunks[i] = jsonChunk{
			Key:        hex.EncodeToString(ch.Key[:]),
			Compressed: ch.Compressed,
			Shards:     shards,
		}
	}
	return json.MarshalIndent(jm, "", "  ")
}

// encodeMeta renders pipeline.Metadata as jsonMeta, or nil when there is nothing
// to record (a v1–v3-style manifest carries no metadata object at all).
func encodeMeta(m pipeline.Metadata) *jsonMeta {
	empty := m.Mode == 0 && m.Uid == 0 && m.Gid == 0 &&
		m.ModTimeNS == 0 && m.ChangeTimeNS == 0 && m.AccessTimeNS == 0 && m.BirthTimeNS == 0 &&
		m.Flags == 0 && m.ContentType == "" && m.SymlinkTarget == "" &&
		len(m.Xattr) == 0 && len(m.ContentVersion) == 0 && len(m.MetaVersion) == 0
	if empty {
		return nil // fully-zero metadata: omit the object entirely (v1–v3 shape)
	}
	jm := &jsonMeta{
		Mode:          m.Mode,
		Uid:           m.Uid,
		Gid:           m.Gid,
		ModTimeNS:     m.ModTimeNS,
		ChangeTimeNS:  m.ChangeTimeNS,
		AccessTimeNS:  m.AccessTimeNS,
		BirthTimeNS:   m.BirthTimeNS,
		Flags:         m.Flags,
		ContentType:   m.ContentType,
		SymlinkTarget: m.SymlinkTarget,
	}
	if len(m.ContentVersion) > 0 {
		jm.ContentVersion = hex.EncodeToString(m.ContentVersion)
	}
	if len(m.MetaVersion) > 0 {
		jm.MetaVersion = hex.EncodeToString(m.MetaVersion)
	}
	if len(m.Xattr) > 0 {
		jm.Xattr = make(map[string]string, len(m.Xattr))
		for k, v := range m.Xattr {
			jm.Xattr[k] = base64.StdEncoding.EncodeToString(v)
		}
	}
	return jm
}

// decodeMeta parses a jsonMeta back into pipeline.Metadata. A nil jm (older
// manifest, or one with no metadata) yields the zero Metadata.
func decodeMeta(jm *jsonMeta) (pipeline.Metadata, error) {
	if jm == nil {
		return pipeline.Metadata{}, nil
	}
	m := pipeline.Metadata{
		Mode:          jm.Mode,
		Uid:           jm.Uid,
		Gid:           jm.Gid,
		ModTimeNS:     jm.ModTimeNS,
		ChangeTimeNS:  jm.ChangeTimeNS,
		AccessTimeNS:  jm.AccessTimeNS,
		BirthTimeNS:   jm.BirthTimeNS,
		Flags:         jm.Flags,
		ContentType:   jm.ContentType,
		SymlinkTarget: jm.SymlinkTarget,
	}
	if jm.ContentVersion != "" {
		v, err := hex.DecodeString(jm.ContentVersion)
		if err != nil {
			return pipeline.Metadata{}, fmt.Errorf("content_version: %w", err)
		}
		m.ContentVersion = v
	}
	if jm.MetaVersion != "" {
		v, err := hex.DecodeString(jm.MetaVersion)
		if err != nil {
			return pipeline.Metadata{}, fmt.Errorf("meta_version: %w", err)
		}
		m.MetaVersion = v
	}
	if len(jm.Xattr) > 0 {
		m.Xattr = make(map[string][]byte, len(jm.Xattr))
		for k, s := range jm.Xattr {
			v, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return pipeline.Metadata{}, fmt.Errorf("xattr %q: %w", k, err)
			}
			m.Xattr[k] = v
		}
	}
	return m, nil
}

// decodeManifest parses JSON produced by encodeManifest back into a
// pipeline.FileManifest, validating key and shard-ID widths.
func decodeManifest(data []byte) (pipeline.FileManifest, error) {
	var jm jsonManifest
	if err := json.Unmarshal(data, &jm); err != nil {
		return pipeline.FileManifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if jm.Version < 1 || jm.Version > manifestVersion {
		return pipeline.FileManifest{}, fmt.Errorf("unsupported manifest version %d (want 1..%d)", jm.Version, manifestVersion)
	}
	meta, err := decodeMeta(jm.Meta)
	if err != nil {
		return pipeline.FileManifest{}, fmt.Errorf("parse metadata: %w", err)
	}
	if len(jm.Chunks) > maxManifestChunks {
		return pipeline.FileManifest{}, fmt.Errorf("manifest: chunk count %d exceeds limit %d", len(jm.Chunks), maxManifestChunks)
	}
	if jm.Size < 0 {
		return pipeline.FileManifest{}, fmt.Errorf("manifest: negative declared size %d", jm.Size)
	}
	m := pipeline.FileManifest{
		Name: jm.Name, // empty for v1 manifests, which carried no name
		Params: pipeline.Config{
			ChunkSize: jm.ChunkSize,
			Params:    erasure.Params{K: jm.K, M: jm.M},
			Compress:  jm.Compress,
		},
		Size:   jm.Size,
		Meta:   meta,
		Chunks: make([]pipeline.ChunkRef, len(jm.Chunks)),
	}
	for i, jc := range jm.Chunks {
		if len(jc.Shards) > maxManifestShardsPerChunk {
			return pipeline.FileManifest{}, fmt.Errorf("chunk %d: shard count %d exceeds limit %d", i, len(jc.Shards), maxManifestShardsPerChunk)
		}
		key, err := decodeKey(jc.Key)
		if err != nil {
			return pipeline.FileManifest{}, fmt.Errorf("chunk %d key: %w", i, err)
		}
		shards := make([]store.ShardID, len(jc.Shards))
		for j, s := range jc.Shards {
			id, err := decodeShardID(s)
			if err != nil {
				return pipeline.FileManifest{}, fmt.Errorf("chunk %d shard %d: %w", i, j, err)
			}
			shards[j] = id
		}
		m.Chunks[i] = pipeline.ChunkRef{Key: key, Compressed: jc.Compressed, Shards: shards}
	}
	return m, nil
}

func decodeKey(s string) (crypto.Key, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return crypto.Key{}, err
	}
	if len(raw) != crypto.KeySize {
		return crypto.Key{}, fmt.Errorf("want %d bytes, got %d", crypto.KeySize, len(raw))
	}
	return crypto.Key(raw), nil
}

func decodeShardID(s string) (store.ShardID, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return store.ShardID{}, err
	}
	if len(raw) != len(store.ShardID{}) {
		return store.ShardID{}, fmt.Errorf("want %d bytes, got %d", len(store.ShardID{}), len(raw))
	}
	return store.ShardID(raw), nil
}
