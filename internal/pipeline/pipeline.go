// Package pipeline is the store/retrieve core: it wires chunking, encryption,
// erasure coding, and the content-addressed store into the two reversible
// operations StoreFile and LoadFile. This is the first end-to-end path — the
// proof that a file can be split, encrypted, dispersed as shards, and rebuilt
// from any K of N — and it runs against any store.Store (mock or networked).
//
// The FileManifest is the recipe to rebuild a file: it is the only thing a
// reader needs besides access to the shards. In the full system a manifest is
// itself encrypted and its location + keys form a read-capability; here it is
// an in-memory value returned by StoreFile and consumed by LoadFile.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"

	"revika/internal/chunk"
	"revika/internal/crypto"
	"revika/internal/erasure"
	"revika/internal/store"
	"revika/internal/stripe"
)

// Config controls how a file is encoded.
type Config struct {
	ChunkSize int            // plaintext bytes per chunk before encryption
	Params    erasure.Params // K data + M parity shards per chunk
}

// DefaultConfig is a sensible starting point: 4 MiB chunks, 4+2 erasure coding.
func DefaultConfig() Config {
	return Config{ChunkSize: chunk.DefaultSize, Params: erasure.Params{K: 4, M: 2}}
}

// ChunkRef records everything needed to rebuild one chunk: its per-chunk
// encryption key and the ordered content addresses of its N shards. Shard
// index maps directly to erasure position (first K are data, rest parity).
type ChunkRef struct {
	Key    crypto.Key
	Shards []store.ShardID
}

// FileManifest is the ordered list of chunk recipes plus the encoding
// parameters, original size, and the file's original name. StoreFile takes an
// io.Reader and cannot know the name, so the caller sets Name after storing
// (see revika-ctl's runStore); it lets a reader restore the file under its
// original name without being told it out of band.
type FileManifest struct {
	Name   string
	Params Config
	Size   int64
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
		ref, err := storeChunk(ctx, s, cfg.Params, plain)
		if err != nil {
			return FileManifest{}, err
		}
		m.Chunks = append(m.Chunks, ref)
		m.Size += int64(len(plain))
	}
	return m, nil
}

func storeChunk(ctx context.Context, s store.Store, p erasure.Params, plain []byte) (ChunkRef, error) {
	key, err := crypto.NewKey()
	if err != nil {
		return ChunkRef{}, err
	}
	sealed, err := crypto.Seal(key, plain)
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
	return ChunkRef{Key: key, Shards: ids}, nil
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
	plain, err := crypto.Open(ref.Key, sealed)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
