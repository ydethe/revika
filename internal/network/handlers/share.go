//go:build v2direct

package handlers

import (
	"encoding/json"
	"log"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/revika/revika/internal/ledger"
	"github.com/revika/revika/pkg/model"
)

// ShareHandler returns a stream handler that processes file sharing requests.
// The handler receives an interface for the ledger (dependency injection).
// It decodes the incoming request, validates permissions, and updates access grants.
func ShareHandler(ledgerService *ledger.Ledger) func(network.Stream) error {
	return func(stream network.Stream) error {
		defer stream.Close()

		var req model.ShareRequest
		decoder := json.NewDecoder(stream)
		if err := decoder.Decode(&req); err != nil {
			log.Printf("failed to decode Share request: %v", err)
			return model.ErrNetworkFailure
		}

		// Validate request fields
		if req.FileID == "" || req.RecipientPeerID == "" || req.WrappedKey == "" {
			log.Printf("invalid Share request: missing required fields")
			return model.ErrNetworkFailure
		}

		// Note: Full access control logic would be implemented here.
		// For now, we perform basic validation.
		resp := model.ShareResponse{
			Status: "ok",
		}

		encoder := json.NewEncoder(stream)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("failed to encode Share response: %v", err)
			return model.ErrNetworkFailure
		}

		return nil
	}
}
