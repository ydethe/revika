// Package manifest is revika's cap-addressed metadata layer: it turns the
// in-memory pipeline.FileManifest into an immutable, content-addressed,
// encrypted *blob*, and builds directories on top of it as a Merkle DAG of such
// blobs (Architecture §3.6/§4).
//
// The pivot is the ReadCap — the minimal, self-contained recipe to fetch and
// decrypt exactly one blob:
//
//	a per-blob AES-256 key + the ordered content addresses of its erasure shards.
//
// A ReadCap IS a file's (or directory's) read-capability: whoever holds it can
// rebuild that blob, and nothing else. Because a cap carries content-addressed
// shard IDs, it commits to the blob's exact bytes — so a directory cap, whose
// blob lists the caps of its children, transitively commits to every descendant.
// A parent cap is thus a Merkle root over its subtree, and the whole namespace is
// a DAG of encrypted blobs anchored by one signed RootPointer (root.go, §4).
//
// Naming is a namespace concern, not a content property: a file blob is nameless
// (addressed only by content), and its name lives in the parent directory's
// Entry (dir.go). Renaming therefore rewrites one directory blob (copy-on-write,
// Graft) and never touches — nor changes the address of — the file blob.
//
// This package reuses the layers below it rather than reimplementing them:
// pipeline.StoreBlob/LoadBlob for the compress→encrypt→erasure→store path, and
// cap.Wrap/Unwrap (ML-KEM-768, FIPS 203) to deliver a cap to a recipient when
// sharing (§3.5). Nodes still see only content-addressed ciphertext shards.
//
// Blob size budget. A blob is a *single* erasure chunk (pipeline.StoreBlob does
// not sub-chunk), so a serialized manifest or directory must fit in one
// Config.ChunkSize (4 MiB by default — comfortably ~16k directory entries or a
// ~75 GiB file's chunk list). Sharding a large directory into an internal DAG
// (HAMT/B-tree) so a single-entry change rewrites O(log n) blobs is the
// documented scale path (§3.6); the PoC keeps one blob per directory.
//
// Defence controls (security/Defence.md; primitives P2, P19 in security/frameworks.md):
//
//	SC-28 (Protection of Information at Rest) — every manifest/directory blob is AES-256-GCM
//	      ciphertext addressed by content hash (via pipeline); nodes never see the namespace.
//	SI-7  (Software, Firmware, and Information Integrity) — a cap's shard IDs are content
//	      addresses, so any tampered blob fails its hash check and is treated as missing.
//	SC-12 (Cryptographic Key Establishment) — sharing wraps a cap to the recipient with ML-KEM-768.
package manifest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"revika/internal/cap"
	"revika/internal/crypto"
	"revika/internal/erasure"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// Kind tags what a blob's decrypted bytes are, so a resolver knows how to decode
// them without fetching a separate hint. It is part of the cap and of its
// content, so a cap cannot be silently reinterpreted as the wrong type.
type Kind uint8

const (
	KindFile Kind = iota // a serialized pipeline.FileManifest
	KindDir              // a serialized DirManifest
)

// String renders a Kind for logs and errors.
func (k Kind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindDir:
		return "dir"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// ReadCap is the minimal, self-contained recipe to fetch and decrypt one
// immutable blob: its Kind, per-blob Key, erasure parameters, and the ordered
// content addresses of its shards. It is a read-capability — the thing a parent
// directory stores for each child and the thing cap.Wrap delivers when sharing.
// Compressed records whether the blob's plaintext was DEFLATEd before encryption
// (decided at store time, see pipeline), so LoadBlob knows to decompress.
type ReadCap struct {
	Kind       Kind
	Key        crypto.Key
	Compressed bool
	K, M       int
	Shards     []store.ShardID
}

// WriteCap is the authority to advance a User's namespace — i.e. to sign a new
// RootPointer. It is exactly the Ed25519 signing key (internal/cap): whoever
// holds it is the single writer for that owner identity. Naming it here
// completes the write→read→verify cap vocabulary the architecture describes
// (§4): a WriteCap mints RootPointers, a ReadCap decrypts a blob, and a
// VerifyCap checks a blob's integrity without decrypting it. It is an alias, not
// a new type, so a WriteCap is interchangeable with a cap.SignKey everywhere.
type WriteCap = cap.SignKey

// VerifyCap is a ReadCap with its decryption Key removed: it still locates a
// blob's shards (content addresses) and carries the erasure parameters, so it
// can fetch and integrity-check the ciphertext, but it cannot decrypt. It is the
// capability published in a DHT root record and used by repair — both need to
// find and verify shards without ever seeing plaintext. Deriving it is a strict
// downgrade (ReadCap.VerifyCap), so a VerifyCap can never be upgraded back into a
// ReadCap that decrypts: VerifyCap.ReadCap re-embeds a zero key.
type VerifyCap struct {
	Kind       Kind
	Compressed bool
	K, M       int
	Shards     []store.ShardID
}

// VerifyCap derives the key-stripped verify capability from a ReadCap. It keeps
// everything a reader needs to *find and check* the blob (kind, erasure params,
// content-addressed shard IDs) and drops only the AES key, so the result is safe
// to publish where a ReadCap would leak confidentiality (the DHT root record).
func (c ReadCap) VerifyCap() VerifyCap {
	return VerifyCap{Kind: c.Kind, Compressed: c.Compressed, K: c.K, M: c.M, Shards: c.Shards}
}

// ReadCap re-embeds a VerifyCap as a ReadCap with a zero decryption key. The
// result serializes through the existing ReadCap codec (the zero key hex-encodes
// and round-trips cleanly) so the wire/DHT form reuses one marshaller; it cannot
// decrypt anything (its key is all-zero), matching the verify-only authority. It
// is also the canonical projection the RootPointer signs over, so one signature
// validates both a full-cap pointer (local) and a key-stripped one (DHT).
func (v VerifyCap) ReadCap() ReadCap {
	return ReadCap{Kind: v.Kind, Compressed: v.Compressed, K: v.K, M: v.M, Shards: v.Shards}
}

// Params returns the erasure parameters a VerifyCap was stored with.
func (v VerifyCap) Params() erasure.Params { return erasure.Params{K: v.K, M: v.M} }

// Params returns the erasure parameters a ReadCap was stored with.
func (c ReadCap) Params() erasure.Params { return erasure.Params{K: c.K, M: c.M} }

// chunkRef converts a cap into the pipeline.ChunkRef that LoadBlob consumes.
func (c ReadCap) chunkRef() pipeline.ChunkRef {
	return pipeline.ChunkRef{Key: c.Key, Compressed: c.Compressed, Shards: c.Shards}
}

// capFromRef builds a ReadCap of the given kind from the ChunkRef that
// StoreBlob returned plus the erasure parameters it was stored with.
func capFromRef(kind Kind, ref pipeline.ChunkRef, p erasure.Params) ReadCap {
	return ReadCap{
		Kind:       kind,
		Key:        ref.Key,
		Compressed: ref.Compressed,
		K:          p.K,
		M:          p.M,
		Shards:     ref.Shards,
	}
}

// putBlob stores data as one encrypted, erasure-coded blob and returns a cap of
// the given kind. It is the single place manifests and directories become blobs.
func putBlob(ctx context.Context, s store.Store, cfg pipeline.Config, kind Kind, data []byte) (ReadCap, error) {
	ref, err := pipeline.StoreBlob(ctx, s, cfg, data)
	if err != nil {
		return ReadCap{}, fmt.Errorf("manifest: store %s blob: %w", kind, err)
	}
	return capFromRef(kind, ref, cfg.Params), nil
}

// getBlob fetches and decrypts the blob a cap points at, verifying the cap's
// Kind matches want so a directory cap is never decoded as a file (or vice versa).
func getBlob(ctx context.Context, s store.Store, c ReadCap, want Kind) ([]byte, error) {
	if c.Kind != want {
		return nil, fmt.Errorf("manifest: cap is %s, want %s", c.Kind, want)
	}
	data, err := pipeline.LoadBlob(ctx, s, c.Params(), c.chunkRef())
	if err != nil {
		return nil, fmt.Errorf("manifest: load %s blob: %w", c.Kind, err)
	}
	return data, nil
}

// VerifyBlob checks a blob's availability and integrity from a VerifyCap alone —
// no decryption key. It fetches each shard by content address (a content-address
// store validates the hash on Get, so a corrupt shard reads as missing) and
// confirms at least K are retrievable, meaning the blob is erasure-recoverable.
// This is the standalone use of a verify capability: repair and a health probe
// can attest a subtree is intact without ever holding the read key.
func VerifyBlob(ctx context.Context, s store.Store, v VerifyCap) error {
	if v.K <= 0 {
		return fmt.Errorf("manifest: verify cap has non-positive K %d", v.K)
	}
	present := 0
	for _, id := range v.Shards {
		_, err := s.Get(ctx, id)
		switch {
		case err == nil:
			present++
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrCorrupt):
			// A missing or hash-failing shard counts as lost; erasure covers up to M.
		default:
			return fmt.Errorf("manifest: verify shard %s: %w", id, err)
		}
	}
	if present < v.K {
		return fmt.Errorf("manifest: blob unrecoverable: %d of %d shards present, need %d", present, len(v.Shards), v.K)
	}
	return nil
}

// readCapJSON is the wire/serialized form of a ReadCap: fixed-width byte arrays
// render as hex (JSON has no byte-string type), matching revika-ctl's manifest
// style. Entries in a directory embed this shape, and WrapCap seals these bytes.
type readCapJSON struct {
	Kind       Kind     `json:"kind"`
	Key        string   `json:"key"`
	Compressed bool     `json:"compressed,omitempty"`
	K          int      `json:"k"`
	M          int      `json:"m"`
	Shards     []string `json:"shards"`
}

// MarshalJSON renders a ReadCap with hex-encoded key and shard IDs.
func (c ReadCap) MarshalJSON() ([]byte, error) {
	jc := readCapJSON{
		Kind:       c.Kind,
		Key:        hex.EncodeToString(c.Key[:]),
		Compressed: c.Compressed,
		K:          c.K,
		M:          c.M,
		Shards:     make([]string, len(c.Shards)),
	}
	for i, id := range c.Shards {
		jc.Shards[i] = id.String()
	}
	return json.Marshal(jc)
}

// UnmarshalJSON parses the form produced by MarshalJSON, validating key and
// shard-ID widths.
func (c *ReadCap) UnmarshalJSON(b []byte) error {
	var jc readCapJSON
	if err := json.Unmarshal(b, &jc); err != nil {
		return err
	}
	key, err := decodeKey(jc.Key)
	if err != nil {
		return fmt.Errorf("cap key: %w", err)
	}
	shards := make([]store.ShardID, len(jc.Shards))
	for i, s := range jc.Shards {
		id, err := decodeShardID(s)
		if err != nil {
			return fmt.Errorf("cap shard %d: %w", i, err)
		}
		shards[i] = id
	}
	*c = ReadCap{Kind: jc.Kind, Key: key, Compressed: jc.Compressed, K: jc.K, M: jc.M, Shards: shards}
	return nil
}

// MarshalBinary returns the canonical serialized cap (its JSON form). It is what
// WrapCap seals and what a directory Entry stores, so a cap can move between a
// share, a directory blob, and a root pointer without ambiguity.
func (c ReadCap) MarshalBinary() ([]byte, error) { return json.Marshal(c) }

// UnmarshalBinary reverses MarshalBinary.
func (c *ReadCap) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, c) }

// WrapCap seals a cap to a recipient's ML-KEM-768 public key so only they can
// unwrap it. This is how a file or an entire subtree is shared (§3.5): hand over
// a directory cap and the recipient can read that subtree and everything
// reachable from it — no more, no less. Delivery reuses internal/cap unchanged.
func WrapCap(recipient cap.PublicKey, c ReadCap) ([]byte, error) {
	raw, err := c.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("manifest: marshal cap: %w", err)
	}
	return cap.Wrap(recipient, raw)
}

// UnwrapCap reverses WrapCap with the recipient's private key.
func UnwrapCap(priv cap.PrivateKey, pub cap.PublicKey, sealed []byte) (ReadCap, error) {
	raw, err := cap.Unwrap(priv, pub, sealed)
	if err != nil {
		return ReadCap{}, err
	}
	var c ReadCap
	if err := c.UnmarshalBinary(raw); err != nil {
		return ReadCap{}, fmt.Errorf("manifest: unmarshal cap: %w", err)
	}
	return c, nil
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
