package shard

// Package shard provides Reed-Solomon erasure coding for file splitting and reconstruction.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
	"github.com/revika/revika/pkg/model"
)

const (
	DefaultK = 3 // data shards needed for reconstruction
	DefaultM = 2 // parity shards for redundancy
)

// ShardSplitter splits a file into erasure-coded shards.
type ShardSplitter struct {
	k int // data shards
	m int // parity shards
}

// NewShardSplitter creates a new ShardSplitter with specified parameters.
// k must be > 0, m must be >= 0, and k+m <= 256 (Reed-Solomon limitation).
func NewShardSplitter(k, m int) (*ShardSplitter, error) {
	if k <= 0 {
		return nil, errors.New("k (data shards) must be > 0")
	}
	if m < 0 {
		return nil, errors.New("m (parity shards) must be >= 0")
	}
	if k+m > 256 {
		return nil, errors.New("k+m must be <= 256")
	}

	return &ShardSplitter{
		k: k,
		m: m,
	}, nil
}

// NewShardSplitterDefault creates a new ShardSplitter with default parameters (k=3, m=2).
func NewShardSplitterDefault() *ShardSplitter {
	return &ShardSplitter{
		k: DefaultK,
		m: DefaultM,
	}
}

// SplitFile splits encrypted file bytes into k+m shards using Reed-Solomon erasure coding.
// The file is already encrypted before calling this function.
// Returns a slice of ShardInfo structs, each with:
//   - ID: SHA256(shard_bytes), hex-encoded
//   - Bytes: the shard data
//   - Index: position in the k+m scheme (0 to k+m-1)
func (ss *ShardSplitter) SplitFile(fileBytes []byte) ([]model.ShardInfo, error) {
	if len(fileBytes) == 0 {
		return nil, errors.New("file bytes cannot be empty")
	}

	// Create Reed-Solomon encoder
	enc, err := reedsolomon.New(ss.k, ss.m)
	if err != nil {
		return nil, fmt.Errorf("failed to create Reed-Solomon encoder: %w", err)
	}

	// Split the file into k data shards (padded) plus m empty parity shards.
	shards, err := enc.Split(fileBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to split file: %w", err)
	}

	// Fill parity shards.
	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("encoding failed: %w", err)
	}

	// Convert shards to ShardInfo with computed IDs
	result := make([]model.ShardInfo, len(shards))
	for i, shardData := range shards {
		result[i] = model.ShardInfo{
			ID:    model.ComputeShardID(shardData),
			Bytes: shardData,
			Index: i,
		}
	}

	return result, nil
}

// ShardReconstructor reconstructs a file from a subset of shards.
type ShardReconstructor struct{}

// NewShardReconstructor creates a new stateless ShardReconstructor.
func NewShardReconstructor() *ShardReconstructor {
	return &ShardReconstructor{}
}

// ReconstructFile reconstructs the original file bytes from any k shards.
// k, m, and originalSize are file-level metadata sourced from the ledger/FileInfo.
// Shards must contain at least k ShardInfo entries and need not be in order
// (position is given by the Index field). Returns the original file bytes.
func (sr *ShardReconstructor) ReconstructFile(shards []model.ShardInfo, k, m int, originalSize int64) ([]byte, error) {
	if k <= 0 {
		return nil, fmt.Errorf("invalid k value: %d", k)
	}
	if len(shards) < k {
		return nil, fmt.Errorf("need at least %d shards, got %d", k, len(shards))
	}

	// Create Reed-Solomon decoder with original k, m values
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, fmt.Errorf("failed to create Reed-Solomon decoder: %w", err)
	}

	totalShards := k + m

	// Verify all shards have the same length
	shardLength := len(shards[0].Bytes)
	for i, shard := range shards {
		if len(shard.Bytes) != shardLength {
			return nil, fmt.Errorf("shard %d has mismatched length: %d vs %d", i, len(shard.Bytes), shardLength)
		}
	}

	// Build the shard array with proper indices; missing shards are left nil.
	decoderShards := make([][]byte, totalShards)
	for _, shard := range shards {
		if shard.Index < 0 || shard.Index >= totalShards {
			return nil, fmt.Errorf("shard index %d out of range [0, %d)", shard.Index, totalShards)
		}
		decoderShards[shard.Index] = shard.Bytes
	}

	// Reconstruct missing shards
	if err := enc.Reconstruct(decoderShards); err != nil {
		return nil, fmt.Errorf("reconstruction failed: %w", err)
	}

	// Join the k data shards and trim to the original file size.
	var buf bytes.Buffer
	if err := enc.Join(&buf, decoderShards, int(originalSize)); err != nil {
		return nil, fmt.Errorf("failed to join shards: %w", err)
	}

	return buf.Bytes(), nil
}

// VerifyShardID verifies that a shard's ID matches SHA256(shard_bytes).
// Returns true if ID is correct, false otherwise.
func VerifyShardID(shard model.ShardInfo) bool {
	expectedID := model.ComputeShardID(shard.Bytes)
	return expectedID == shard.ID
}

// VerifyShardIntegrity verifies a shard has not been corrupted by computing its hash.
func VerifyShardIntegrity(shardBytes []byte) [sha256.Size]byte {
	return sha256.Sum256(shardBytes)
}
