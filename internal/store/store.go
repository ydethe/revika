// Package store defines revika's content-addressed shard store: the seam every
// higher layer targets. A shard's identifier IS the hash of its bytes, so the
// store is self-verifying (tampered or truncated data fails its ID check) and
// idempotent (storing identical bytes twice yields the same ID).
//
// The Store interface deliberately knows nothing about encryption, erasure
// coding, or the network. That is what lets the encode/repair stack be built
// and tested against the in-memory or on-disk implementations here, then run
// unchanged against a future libp2p-backed implementation.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrNotFound is returned by Get/Delete when a shard is absent.
var ErrNotFound = errors.New("store: shard not found")

// ErrCorrupt is returned by Get when stored bytes no longer hash to their ID.
var ErrCorrupt = errors.New("store: shard failed integrity check")

// ShardID is the content address of a shard: the SHA-256 of its bytes.
type ShardID [sha256.Size]byte

// HashOf returns the ShardID that addresses data.
func HashOf(data []byte) ShardID { return sha256.Sum256(data) }

// String renders the ID as lowercase hex.
func (id ShardID) String() string { return hex.EncodeToString(id[:]) }

// Store is a content-addressed blob store. Implementations must be safe for
// concurrent use.
type Store interface {
	// Put stores data and returns its content address. Putting identical
	// bytes more than once is a no-op that returns the same ID.
	Put(ctx context.Context, data []byte) (ShardID, error)
	// Get returns the bytes for id, or ErrNotFound. Implementations verify
	// that the returned bytes hash to id and return ErrCorrupt otherwise.
	Get(ctx context.Context, id ShardID) ([]byte, error)
	// Has reports whether id is present.
	Has(ctx context.Context, id ShardID) (bool, error)
	// Delete removes id. Deleting an absent shard returns ErrNotFound.
	Delete(ctx context.Context, id ShardID) error
}

// Lister is an optional capability a Store may implement: enumerate the IDs of
// every shard it currently holds. It is deliberately kept off the core Store
// interface (not every backend can cheaply enumerate) — callers type-assert for
// it. A Node uses this to re-announce its DHT provider records on startup and on
// a periodic reprovide cadence.
type Lister interface {
	List(ctx context.Context) ([]ShardID, error)
}
