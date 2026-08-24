package node

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/revika/revika/internal/ipfs"
	"github.com/revika/revika/internal/ipfs/kubo"
	"github.com/revika/revika/internal/ledger"
	"github.com/revika/revika/internal/store"
	"github.com/revika/revika/pkg/model"
)

// Server is the Node server that stores shards and participates in the network.
// The store remains the store of record; the IPFS backend provides
// content-addressed distribution.
type Server struct {
	store      store.FileBackend
	backend    ipfs.BlockStore
	peerInfo   ipfs.PeerInfo
	ledger     *ledger.Ledger
	ctx        context.Context
	cancel     context.CancelFunc
	storeDir   string
	ledgerPath string
}

// NewServer creates a new Node server backed by a Kubo IPFS adapter.
// apiAddr is the Kubo RPC API address (e.g. "127.0.0.1:5001"). Adapter
// construction is lazy, so a server can be created without a running daemon.
// Returns model.ErrNetworkFailure if initialization fails.
func NewServer(storeDir string, ledgerPath string, apiAddr string) (*Server, error) {
	// Create store directory if it doesn't exist
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	// Create file-based store
	fileStore, err := store.NewLocalFileStore(storeDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create file store: %w", err)
	}

	// Load ledger (or create empty)
	nodeledger, err := ledger.Load(ledgerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ledger: %w", err)
	}

	// Create the Kubo IPFS backend (lazy: no daemon contact yet)
	backend, err := kubo.NewAdapter(apiAddr)
	if err != nil {
		return nil, err
	}

	// Create context for lifecycle
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		store:      fileStore,
		backend:    backend,
		peerInfo:   backend,
		ledger:     nodeledger,
		ctx:        ctx,
		cancel:     cancel,
		storeDir:   storeDir,
		ledgerPath: ledgerPath,
	}, nil
}

// Start starts the Node server. For V1 it verifies the Kubo backend is
// reachable by querying its peer ID and logs readiness. It does not register
// libp2p protocol handlers (that is the dormant V2 path).
func (s *Server) Start() error {
	peerID := s.GetPeerID()
	if peerID != "" {
		log.Printf("Node server ready (IPFS peer ID: %s)", peerID)
	} else {
		log.Printf("Node server ready (IPFS backend not yet reachable)")
	}
	return nil
}

// StoreShard persists an encrypted shard to both the store of record and the
// IPFS backend, then advertises it to the DHT. V1 intentionally holds the bytes
// twice (store + pin), accepting ~2x disk in exchange for a simple design.
// The returned ShardRef carries the integrity hash and the network CID.
func (s *Server) StoreShard(ctx context.Context, data []byte) (model.ShardRef, error) {
	hash := model.ComputeShardID(data)

	// Store of record.
	if err := s.store.PutShard(hash, data); err != nil {
		return model.ShardRef{}, fmt.Errorf("failed to store shard: %w", err)
	}

	// Content-addressed network copy.
	cid, err := s.backend.AddBlock(ctx, data)
	if err != nil {
		return model.ShardRef{}, fmt.Errorf("failed to add shard to IPFS: %w", err)
	}

	// Best-effort DHT advertisement.
	if err := s.backend.Provide(ctx, cid); err != nil {
		log.Printf("failed to advertise shard %s: %v", cid, err)
	}

	return model.ShardRef{Hash: hash, CID: cid, Index: 0}, nil
}

// Stop gracefully shuts down the server by saving the ledger and cancelling
// the lifecycle context.
func (s *Server) Stop() error {
	log.Printf("Stopping Node server")

	// Save ledger before shutdown
	if err := s.ledger.Save(s.ledgerPath); err != nil {
		log.Printf("failed to save ledger on shutdown: %v", err)
	}

	s.cancel()
	return nil
}

// GetStats returns node storage statistics.
// Returns a map with keys: "shards", "total_size", "connected_peers".
func (s *Server) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count shards
	shards, err := s.store.ListShards()
	if err != nil {
		return nil, fmt.Errorf("failed to list shards: %w", err)
	}
	stats["shards"] = len(shards)

	// Calculate total size
	totalSize := int64(0)
	for _, shardID := range shards {
		data, err := s.store.GetShard(shardID)
		if err != nil {
			log.Printf("failed to get shard %s for stats: %v", shardID, err)
			continue
		}
		totalSize += int64(len(data))
	}
	stats["total_size"] = totalSize

	// Get connected peers from the IPFS backend
	peers, err := s.peerInfo.Peers(s.ctx)
	if err != nil {
		stats["connected_peers"] = 0
	} else {
		stats["connected_peers"] = len(peers)
	}

	return stats, nil
}

// GetPeerID returns the IPFS peer ID of this node, or "" if unreachable.
func (s *Server) GetPeerID() string {
	id, err := s.peerInfo.ID(s.ctx)
	if err != nil {
		return ""
	}
	return id
}
