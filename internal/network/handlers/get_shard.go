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

// GetShardHandler returns a stream handler that retrieves a shard from the local node.
// The handler receives an interface for the shard store (dependency injection).
// It decodes the incoming request, retrieves the shard, and sends a response.
func GetShardHandler(fileStore store.FileBackend) func(network.Stream) error {
	return func(stream network.Stream) error {
		defer stream.Close()

		var req model.GetShardRequest
		decoder := json.NewDecoder(stream)
		if err := decoder.Decode(&req); err != nil {
			log.Printf("failed to decode GetShard request: %v", err)
			return model.ErrNetworkFailure
		}

		// Retrieve the shard
		data, err := fileStore.GetShard(req.ShardID)
		if err != nil {
			log.Printf("failed to retrieve shard: %v", err)
			return model.ErrNetworkFailure
		}

		// Encode data as base64
		encodedData := base64.StdEncoding.EncodeToString(data)

		// Send response
		resp := model.GetShardResponse{
			ShardID: req.ShardID,
			Data:    encodedData,
			Size:    int64(len(data)),
		}

		encoder := json.NewEncoder(stream)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("failed to encode GetShard response: %v", err)
			return model.ErrNetworkFailure
		}

		return nil
	}
}
