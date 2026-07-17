package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"revika/internal/crypto"
	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// manifestVersion tags the on-disk format so a future reader can detect and
// migrate older files.
const manifestVersion = 1

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
	ChunkSize int         `json:"chunk_size"`
	K         int         `json:"k"`
	M         int         `json:"m"`
	Size      int64       `json:"size"`
	Chunks    []jsonChunk `json:"chunks"`
}

type jsonChunk struct {
	Key    string   `json:"key"`    // hex of the 32-byte per-chunk AES key
	Shards []string `json:"shards"` // hex of each 32-byte shard content address
}

// encodeManifest renders m as indented JSON.
func encodeManifest(m pipeline.FileManifest) ([]byte, error) {
	jm := jsonManifest{
		Version:   manifestVersion,
		ChunkSize: m.Params.ChunkSize,
		K:         m.Params.Params.K,
		M:         m.Params.Params.M,
		Size:      m.Size,
		Chunks:    make([]jsonChunk, len(m.Chunks)),
	}
	for i, ch := range m.Chunks {
		shards := make([]string, len(ch.Shards))
		for j, id := range ch.Shards {
			shards[j] = id.String()
		}
		jm.Chunks[i] = jsonChunk{
			Key:    hex.EncodeToString(ch.Key[:]),
			Shards: shards,
		}
	}
	return json.MarshalIndent(jm, "", "  ")
}

// decodeManifest parses JSON produced by encodeManifest back into a
// pipeline.FileManifest, validating key and shard-ID widths.
func decodeManifest(data []byte) (pipeline.FileManifest, error) {
	var jm jsonManifest
	if err := json.Unmarshal(data, &jm); err != nil {
		return pipeline.FileManifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if jm.Version != manifestVersion {
		return pipeline.FileManifest{}, fmt.Errorf("unsupported manifest version %d (want %d)", jm.Version, manifestVersion)
	}
	m := pipeline.FileManifest{
		Params: pipeline.Config{
			ChunkSize: jm.ChunkSize,
			Params:    erasure.Params{K: jm.K, M: jm.M},
		},
		Size:   jm.Size,
		Chunks: make([]pipeline.ChunkRef, len(jm.Chunks)),
	}
	for i, jc := range jm.Chunks {
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
		m.Chunks[i] = pipeline.ChunkRef{Key: key, Shards: shards}
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
