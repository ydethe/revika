package model

import "errors"

// Static error types for network, storage, and access operations.
// Per Phase 1's oracle-avoidance policy, errors are defined as static variables
// rather than being dynamically generated.

var (
	// ErrNetworkFailure indicates a network request failed.
	ErrNetworkFailure = errors.New("network request failed")

	// ErrPeerNotFound indicates a peer was not found in the network.
	ErrPeerNotFound = errors.New("peer not found")

	// ErrShardNotFound indicates a shard was not found in storage.
	ErrShardNotFound = errors.New("shard not found")

	// ErrLedgerCorrupted indicates the ledger is corrupted or cannot be parsed.
	ErrLedgerCorrupted = errors.New("ledger corrupted")

	// ErrAccessDenied indicates access is denied (insufficient permissions).
	ErrAccessDenied = errors.New("access denied")

	// ErrInvalidPath indicates a path is invalid or malformed.
	ErrInvalidPath = errors.New("invalid path")

	// ErrFileNotFound indicates a file was not found.
	ErrFileNotFound = errors.New("file not found")

	// ErrNotDirectory indicates the path is not a directory.
	ErrNotDirectory = errors.New("not a directory")
)
