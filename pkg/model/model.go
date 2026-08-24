package model

// Package model defines shared types for Revika Phase 1.

import (
	"crypto/sha256"
	"fmt"
)

// ShardInfo represents an encrypted shard of a file.
type ShardInfo struct {
	ID    string // SHA256(encrypted_shard_bytes), hex-encoded
	Bytes []byte // encrypted shard data
	Index int    // position in k+m erasure coding scheme (0 to k+m-1)
	CID   string // IPFS CIDv1 network address (empty until stored on the network)
}

// ShardRef references a stored shard in the ledger by both its integrity
// hash and its IPFS network address.
type ShardRef struct {
	Hash  string // sha2-256 hex (integrity)
	CID   string // IPFS CIDv1 (network address)
	Index int    // position in the k+m array
}

// FileInfo represents metadata about a file before sharding.
type FileInfo struct {
	Name            string            // original filename
	ContentHash     [sha256.Size]byte // SHA256 of original plaintext
	EncryptedHash   [sha256.Size]byte // SHA256 of encrypted content
	Size            int64             // original file size in bytes
	ShardCount      int               // k + m (total shards)
	DataShards      int               // k (data shards needed for reconstruction)
	ParityShards    int               // m (parity shards for redundancy)
	CreatedAt       int64             // Unix timestamp
	Owner           string            // device identifier (not enforced in Phase 1)
	GrantedToPublic []byte            // Ed25519 public keys of recipients (recipients can decrypt)
}

// LedgerEntry tracks a shard stored on this node.
type LedgerEntry struct {
	ShardID   string // unique shard identifier
	FilePath  string // path where shard is stored on disk
	Size      int64  // shard size in bytes
	CreatedAt int64  // Unix timestamp of when shard was stored
}

// ComputeShardID computes the shard ID as SHA256(encrypted_shard_bytes), hex-encoded.
// Used by shard/ package for deterministic, content-addressed shards.
func ComputeShardID(shardBytes []byte) string {
	hash := sha256.Sum256(shardBytes)
	return fmt.Sprintf("%x", hash)
}
