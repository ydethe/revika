package manifest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// fileManifestVersion tags the serialized file-manifest blob so a future reader
// can detect and migrate older formats. It mirrors revika-ctl's on-disk manifest
// (the local-JSON form this cap-addressed blob supersedes) and stays in step
// with it; v4 carries filesystem metadata (mode/uid/gid/times/flags/…).
const fileManifestVersion = 4

// fileManifestJSON is the serialized form of a pipeline.FileManifest that
// becomes a KindFile blob. It is deliberately the same shape as revika-ctl's
// jsonManifest so a manifest can move from a local JSON file into a cap-addressed
// blob (and back) without reshaping. pipeline.Metadata marshals directly here —
// encoding/json renders its []byte fields (xattr values, version tokens) as
// base64 and sorts map keys — so only the fixed-width key and shard IDs need
// hex handling.
type fileManifestJSON struct {
	Version   int               `json:"version"`
	Name      string            `json:"name,omitempty"`
	ChunkSize int               `json:"chunk_size"`
	K         int               `json:"k"`
	M         int               `json:"m"`
	Compress  bool              `json:"compress,omitempty"`
	Size      int64             `json:"size"`
	Meta      pipeline.Metadata `json:"meta,omitzero"`
	Chunks    []fileChunkJSON   `json:"chunks"`
}

type fileChunkJSON struct {
	Key        string   `json:"key"`
	Compressed bool     `json:"compressed,omitempty"`
	Shards     []string `json:"shards"`
}

// EncodeFileManifest renders a pipeline.FileManifest as the canonical JSON that
// a KindFile blob holds. It is exported so revika-ctl and future callers share
// one codec rather than diverging (the planned move of the on-disk manifest into
// this package, Architecture §3.6).
func EncodeFileManifest(m pipeline.FileManifest) ([]byte, error) {
	jm := fileManifestJSON{
		Version:   fileManifestVersion,
		Name:      m.Name,
		ChunkSize: m.Params.ChunkSize,
		K:         m.Params.Params.K,
		M:         m.Params.Params.M,
		Compress:  m.Params.Compress,
		Size:      m.Size,
		Meta:      m.Meta,
		Chunks:    make([]fileChunkJSON, len(m.Chunks)),
	}
	for i, ch := range m.Chunks {
		shards := make([]string, len(ch.Shards))
		for j, id := range ch.Shards {
			shards[j] = id.String()
		}
		jm.Chunks[i] = fileChunkJSON{
			Key:        hex.EncodeToString(ch.Key[:]),
			Compressed: ch.Compressed,
			Shards:     shards,
		}
	}
	return json.Marshal(jm)
}

// DecodeFileManifest parses JSON produced by EncodeFileManifest.
func DecodeFileManifest(data []byte) (pipeline.FileManifest, error) {
	var jm fileManifestJSON
	if err := json.Unmarshal(data, &jm); err != nil {
		return pipeline.FileManifest{}, fmt.Errorf("manifest: parse file manifest: %w", err)
	}
	if jm.Version < 1 || jm.Version > fileManifestVersion {
		return pipeline.FileManifest{}, fmt.Errorf("manifest: unsupported file manifest version %d (want 1..%d)", jm.Version, fileManifestVersion)
	}
	m := pipeline.FileManifest{
		Name: jm.Name,
		Params: pipeline.Config{
			ChunkSize: jm.ChunkSize,
			Params:    erasure.Params{K: jm.K, M: jm.M},
			Compress:  jm.Compress,
		},
		Size:   jm.Size,
		Meta:   jm.Meta,
		Chunks: make([]pipeline.ChunkRef, len(jm.Chunks)),
	}
	for i, jc := range jm.Chunks {
		key, err := decodeKey(jc.Key)
		if err != nil {
			return pipeline.FileManifest{}, fmt.Errorf("manifest: chunk %d key: %w", i, err)
		}
		shards := make([]store.ShardID, len(jc.Shards))
		for j, s := range jc.Shards {
			id, err := decodeShardID(s)
			if err != nil {
				return pipeline.FileManifest{}, fmt.Errorf("manifest: chunk %d shard %d: %w", i, j, err)
			}
			shards[j] = id
		}
		m.Chunks[i] = pipeline.ChunkRef{Key: key, Compressed: jc.Compressed, Shards: shards}
	}
	return m, nil
}

// StoreFileManifest serializes a pipeline.FileManifest and stores it as an
// immutable, encrypted KindFile blob, returning the cap that addresses it. That
// cap is the file's read-capability: it is what a directory Entry points at and
// what WrapCap shares. cfg controls how the manifest *blob* is encoded (its own
// key/erasure), independent of how the file's data chunks were encoded.
func StoreFileManifest(ctx context.Context, s store.Store, cfg pipeline.Config, m pipeline.FileManifest) (ReadCap, error) {
	data, err := EncodeFileManifest(m)
	if err != nil {
		return ReadCap{}, fmt.Errorf("manifest: encode file manifest: %w", err)
	}
	return putBlob(ctx, s, cfg, KindFile, data)
}

// LoadFileManifest fetches and decrypts the KindFile blob a cap points at and
// decodes it back into a pipeline.FileManifest (from which pipeline.LoadFile
// then reconstructs the file's bytes).
func LoadFileManifest(ctx context.Context, s store.Store, c ReadCap) (pipeline.FileManifest, error) {
	data, err := getBlob(ctx, s, c, KindFile)
	if err != nil {
		return pipeline.FileManifest{}, err
	}
	return DecodeFileManifest(data)
}
