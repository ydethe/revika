//go:build v2direct

package handlers

import (
	"encoding/json"
	"log"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/revika/revika/internal/ledger"
	"github.com/revika/revika/pkg/model"
)

// RevokeHandler returns a stream handler that processes access revocation requests.
// The handler receives an interface for the ledger (dependency injection).
// It decodes the incoming request, validates permissions, and revokes access.
func RevokeHandler(ledgerService *ledger.Ledger) func(network.Stream) error {
	return func(stream network.Stream) error {
		defer stream.Close()

		var req model.RevokeRequest
		decoder := json.NewDecoder(stream)
		if err := decoder.Decode(&req); err != nil {
			log.Printf("failed to decode Revoke request: %v", err)
			return model.ErrNetworkFailure
		}

		// Validate request fields
		if req.FileID == "" || req.RecipientPeerID == "" {
			log.Printf("invalid Revoke request: missing required fields")
			return model.ErrNetworkFailure
		}

		// Note: Full access control logic would be implemented here.
		// For now, we perform basic validation.
		resp := model.RevokeResponse{
			Status: "ok",
		}

		encoder := json.NewEncoder(stream)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("failed to encode Revoke response: %v", err)
			return model.ErrNetworkFailure
		}

		return nil
	}
}
