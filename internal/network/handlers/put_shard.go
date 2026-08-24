//go:build v2direct

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/revika/revika/internal/store"
	"github.com/revika/revika/pkg/model"
)

// PutShardHandler returns a stream handler that stores a shard on the local node.
// The handler receives an interface for the shard store (dependency injection).
// It decodes the incoming request, stores the shard, and sends a response.
func PutShardHandler(fileStore store.FileBackend) func(network.Stream) error {
	return func(stream network.Stream) error {
		defer stream.Close()

		var req model.PutShardRequest
		decoder := json.NewDecoder(stream)
		if err := decoder.Decode(&req); err != nil {
			log.Printf("failed to decode PutShard request: %v", err)
			return model.ErrNetworkFailure
		}

		// Decode base64 data
		decodedData, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			log.Printf("failed to decode shard data: %v", err)
			return model.ErrNetworkFailure
		}

		// Store the shard
		if err := fileStore.PutShard(req.ShardID, decodedData); err != nil {
			log.Printf("failed to store shard: %v", err)
			return model.ErrNetworkFailure
		}

		// Send response
		resp := model.PutShardResponse{
			ShardID: req.ShardID,
			Size:    int64(len(decodedData)),
		}

		encoder := json.NewEncoder(stream)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("failed to encode PutShard response: %v", err)
			return model.ErrNetworkFailure
		}

		return nil
	}
}
