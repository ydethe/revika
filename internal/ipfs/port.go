// Package ipfs defines revika's IPFS port: a set of capability-segregated
// interfaces that the rest of the system consumes to reach a content-addressed
// network. The port speaks only in revika terms ([]byte payloads and string
// content hashes) and never leaks IPFS/CID/libp2p types to its consumers.
//
// Two backends satisfy this port:
//   - V1 (default): internal/ipfs/kubo — a thin adapter over an external Kubo
//     daemon's RPC HTTP API.
//   - V2 (dormant, build tag "v2direct"): internal/network — a direct go-libp2p
//     implementation kept for future in-process operation.
//
// IMPORT INVARIANT: only internal/ipfs/kubo may import Kubo, go-cid, or
// libp2p packages. Consumers (internal/node, internal/daemon, internal/cli,
// pkg/model) MUST NOT import go-ipfs-api, kubo/*, go-cid, or libp2p/*.
package ipfs

import "context"

// BlockStore is the content-addressed block capability consumed by the Node.
// Implementations add/fetch/pin/advertise single-block, encrypted shards.
type BlockStore interface {
	// AddBlock stores raw bytes as a single-block CIDv1 (raw codec, sha2-256),
	// pins it, and returns the resulting CID string. The multihash inside the
	// CID is the sha2-256 of data, matching model.ComputeShardID.
	AddBlock(ctx context.Context, data []byte) (cid string, err error)
	// GetBlock fetches block bytes by CID string.
	GetBlock(ctx context.Context, cid string) ([]byte, error)
	// Pin pins an existing CID locally.
	Pin(ctx context.Context, cid string) error
	// Provide advertises the CID to the DHT so other peers can find it.
	Provide(ctx context.Context, cid string) error
}

// NameService is the mutable-pointer (IPNS) capability consumed by the Daemon.
type NameService interface {
	// PublishIPNS publishes a value (e.g. an encrypted root CID) under this
	// node's IPNS key and returns the IPNS name.
	PublishIPNS(ctx context.Context, valueCID string) (name string, err error)
	// ResolveIPNS resolves an IPNS name to its current value CID.
	ResolveIPNS(ctx context.Context, name string) (valueCID string, err error)
}

// PeerInfo is the identity/connectivity capability.
type PeerInfo interface {
	// ID returns this node's IPFS peer ID.
	ID(ctx context.Context) (string, error)
	// Peers returns the peer IDs this node is currently connected to.
	Peers(ctx context.Context) ([]string, error)
	// Connect connects to a peer by multiaddr.
	Connect(ctx context.Context, multiaddr string) error
}

// Messaging (ledger-sync / share / revoke overlays) is DEFERRED for V1.
// It is defined for forward-compatibility but is not implemented or wired.
type Messaging interface {
	Publish(ctx context.Context, topic string, data []byte) error
	Subscribe(ctx context.Context, topic string) (<-chan []byte, error)
}

// Backend is the full IPFS surface. The Kubo adapter implements BlockStore,
// NameService, and PeerInfo; Messaging is deferred.
type Backend interface {
	BlockStore
	NameService
	PeerInfo
}
