// Package pipeline is the store/retrieve core: it wires chunking, optional
// compression, encryption, erasure coding, and the content-addressed store into
// the two reversible operations StoreFile and LoadFile. This is the first end-to-end path — the
// proof that a file can be split, encrypted, dispersed as shards, and rebuilt
// from any K of N — and it runs against any store.Store (mock or networked).
//
// The FileManifest is the recipe to rebuild a file: it is the only thing a
// reader needs besides access to the shards. In the full system a manifest is
// itself encrypted and its location + keys form a read-capability; here it is
// an in-memory value returned by StoreFile and consumed by LoadFile.
//
// Defence controls (security/Defence.md; primitives P1, P6, P23 in security/frameworks.md):
//
//	SA-8  (Security and Privacy Engineering Principles) — all chunking, encryption, and erasure
//	      coding happen client-side here before any shard leaves the machine.
//	SC-28 (Protection of Information at Rest)  — shards are AES-256-GCM ciphertext when stored (internal/crypto).
//	SC-36 (Distributed Processing and Storage) — each chunk is erasure-coded into K+M dispersible shards.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"

	"revika/internal/chunk"
	"revika/internal/compress"
	"revika/internal/crypto"
	"revika/internal/erasure"
	"revika/internal/store"
	"revika/internal/stripe"
)

// Config controls how a file is encoded.
type Config struct {
	ChunkSize int            // plaintext bytes per chunk before encryption
	Params    erasure.Params // K data + M parity shards per chunk
	Compress  bool           // DEFLATE each chunk before encrypting (see internal/compress)
}

// DefaultConfig is a sensible starting point: 4 MiB chunks, 4+2 erasure coding,
// with compression enabled (it is skipped per chunk when it would not help).
func DefaultConfig() Config {
	return Config{ChunkSize: chunk.DefaultSize, Params: erasure.Params{K: 4, M: 2}, Compress: true}
}

// ChunkRef records everything needed to rebuild one chunk: its per-chunk
// encryption key, whether the plaintext was compressed before encryption, and
// the ordered content addresses of its N shards. Shard index maps directly to
// erasure position (first K are data, rest parity). Compressed is decided per
// chunk at store time (only kept when it shrinks the data), so LoadFile relies
// on this flag rather than the Config to know whether to decompress.
type ChunkRef struct {
	Key        crypto.Key
	Compressed bool
	Shards     []store.ShardID
}

// FileManifest is the ordered list of chunk recipes plus the encoding
// parameters, original size, the file's original name, and its filesystem
// metadata. StoreFile takes an io.Reader and cannot know the name or the
// on-disk attributes, so the caller sets Name and Meta after storing (see
// revika-ctl's runStore); together they let a reader restore the file under its
// original name and attributes — and let a native cloud-provider mount (macOS
// File Provider, Windows Cloud Filter; Architecture §3.8) present it as a
// placeholder without hydrating the shards.
type FileManifest struct {
	Name   string
	Params Config
	Size   int64
	Meta   Metadata
	Chunks []ChunkRef
}

// StoreFile chunks, encrypts, erasure-codes, and stores r, returning a manifest
// that LoadFile can use to reconstruct it. Shards are addressed by content
// hash, so identical shards across chunks are stored once.
func StoreFile(ctx context.Context, s store.Store, cfg Config, r io.Reader) (FileManifest, error) {
	m := FileManifest{Params: cfg}
	for plain, err := range chunk.Fixed(r, cfg.ChunkSize) {
		if err != nil {
			return FileManifest{}, err
		}
		ref, err := storeChunk(ctx, s, cfg, plain)
		if err != nil {
			return FileManifest{}, err
		}
		m.Chunks = append(m.Chunks, ref)
		m.Size += int64(len(plain))
	}
	return m, nil
}

func storeChunk(ctx context.Context, s store.Store, cfg Config, plain []byte) (ChunkRef, error) {
	p := cfg.Params

	// Compression runs on plaintext, before encryption — ciphertext is
	// incompressible. Keep the compressed form only when it actually shrinks the
	// chunk, so incompressible data (already-compressed files) is not expanded.
	payload := plain
	compressed := false
	if cfg.Compress {
		packed, err := compress.Compress(plain)
		if err != nil {
			return ChunkRef{}, err
		}
		if len(packed) < len(plain) {
			payload = packed
			compressed = true
		}
	}

	key, err := crypto.NewKey()
	if err != nil {
		return ChunkRef{}, err
	}
	sealed, err := crypto.Seal(key, payload)
	if err != nil {
		return ChunkRef{}, err
	}
	shards, err := erasure.Encode(p, sealed)
	if err != nil {
		return ChunkRef{}, err
	}

	// Erasure.Encode returns all N shards at once, so every shard's content
	// address is known before the first Put — which lets us build the stripe
	// Descriptor (the non-confidential erasure context: K, M, and the ordered
	// shard IDs) and hand it to the store. A store that implements stripe.Putter
	// (a networked PlacementStore) records the descriptor on each node so it can
	// later repair the stripe; a plain store (mock/in-memory) just gets Put.
	ids := make([]store.ShardID, len(shards))
	for i, sh := range shards {
		ids[i] = store.HashOf(sh)
	}
	desc := stripe.Descriptor{K: p.K, M: p.M, Shards: ids}

	sp, stripeAware := s.(stripe.Putter)
	for i, sh := range shards {
		var id store.ShardID
		var err error
		if stripeAware {
			id, err = sp.PutStripe(ctx, sh, desc)
		} else {
			id, err = s.Put(ctx, sh)
		}
		if err != nil {
			return ChunkRef{}, fmt.Errorf("pipeline: put shard %d: %w", i, err)
		}
		if id != ids[i] {
			return ChunkRef{}, fmt.Errorf("pipeline: shard %d stored as %s, want %s", i, id, ids[i])
		}
	}
	return ChunkRef{Key: key, Compressed: compressed, Shards: ids}, nil
}

// StoreBlob stores data as a single self-contained erasure-coded chunk and
// returns the ChunkRef needed to reload it. It is the base primitive under
// cap-addressed manifests and directories (internal/manifest): a small immutable
// blob — a serialized file manifest or directory — referenced compactly by its
// ChunkRef (per-blob key + ordered shard IDs). Unlike StoreFile it does not
// chunk: the caller is responsible for keeping a blob within one chunk (see
// internal/manifest for the size budget and the sharding path for larger ones).
func StoreBlob(ctx context.Context, s store.Store, cfg Config, data []byte) (ChunkRef, error) {
	return storeChunk(ctx, s, cfg, data)
}

// LoadBlob reverses StoreBlob: it fetches the blob's shards (tolerating missing
// ones up to the erasure margin), erasure-decodes, decrypts, and decompresses,
// returning the original bytes.
func LoadBlob(ctx context.Context, s store.Store, p erasure.Params, ref ChunkRef) ([]byte, error) {
	return loadChunk(ctx, s, p, ref)
}

// LoadFile reconstructs the file described by m and writes it to w. For each
// chunk it fetches whatever shards are available (missing ones are tolerated up
// to the erasure margin), decodes, and decrypts.
func LoadFile(ctx context.Context, s store.Store, m FileManifest, w io.Writer) error {
	for i, ref := range m.Chunks {
		plain, err := loadChunk(ctx, s, m.Params.Params, ref)
		if err != nil {
			return fmt.Errorf("pipeline: chunk %d: %w", i, err)
		}
		if _, err := w.Write(plain); err != nil {
			return fmt.Errorf("pipeline: write: %w", err)
		}
	}
	return nil
}

func loadChunk(ctx context.Context, s store.Store, p erasure.Params, ref ChunkRef) ([]byte, error) {
	shards := make([][]byte, len(ref.Shards))
	for i, id := range ref.Shards {
		data, err := s.Get(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrCorrupt) {
				continue // treat missing/corrupt as a lost shard; erasure covers it
			}
			return nil, fmt.Errorf("get shard %d: %w", i, err)
		}
		shards[i] = data
	}
	sealed, err := erasure.Decode(p, shards)
	if err != nil {
		return nil, err
	}
	payload, err := crypto.Open(ref.Key, sealed)
	if err != nil {
		return nil, err
	}
	if ref.Compressed {
		return compress.Decompress(payload)
	}
	return payload, nil
}
