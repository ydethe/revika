package model

// Network protocol message types for Revika's libp2p-based protocols.

// Shard storage protocol messages

// PutShardRequest represents a request to store a shard on a node.
type PutShardRequest struct {
	ShardID string `json:"shard_id"` // hex-encoded SHA256 hash
	Data    string `json:"data"`     // base64-encoded encrypted shard data
}

// PutShardResponse represents the response after storing a shard.
type PutShardResponse struct {
	ShardID string `json:"shard_id"`
	Size    int64  `json:"size"`
}

// GetShardRequest represents a request to retrieve a shard from a node.
type GetShardRequest struct {
	ShardID string `json:"shard_id"` // hex-encoded SHA256 hash
}

// GetShardResponse represents the response containing a shard.
type GetShardResponse struct {
	ShardID string `json:"shard_id"`
	Data    string `json:"data"` // base64-encoded encrypted shard data
	Size    int64  `json:"size"`
}

// Ledger synchronization protocol messages

// LedgerSyncRequest represents a request to synchronize ledger state.
type LedgerSyncRequest struct {
	TreeID string                 `json:"tree_id"`
	Ledger map[string]interface{} `json:"ledger"` // simplified for now
}

// LedgerSyncResponse represents the response to a ledger sync request.
type LedgerSyncResponse struct {
	Status string `json:"status"` // "ok" or error message
}

// Access sharing protocol messages

// ShareRequest represents a request to share a file with another peer.
type ShareRequest struct {
	FileID          string `json:"file_id"`
	RecipientPeerID string `json:"recipient_peer_id"`
	WrappedKey      string `json:"wrapped_key"` // base64-encoded wrapped encryption key
}

// ShareResponse represents the response to a share request.
type ShareResponse struct {
	Status string `json:"status"`
}

// RevokeRequest represents a request to revoke access to a file.
type RevokeRequest struct {
	FileID          string `json:"file_id"`
	RecipientPeerID string `json:"recipient_peer_id"`
}

// RevokeResponse represents the response to a revoke request.
type RevokeResponse struct {
	Status string `json:"status"`
}
