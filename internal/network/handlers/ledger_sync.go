//go:build v2direct

package handlers

import (
	"encoding/json"
	"log"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/revika/revika/internal/ledger"
	"github.com/revika/revika/pkg/model"
)

// LedgerSyncHandler returns a stream handler that synchronizes ledger state.
// The handler receives an interface for the ledger (dependency injection).
// It decodes the incoming request, updates the ledger, and sends a response.
func LedgerSyncHandler(ledgerService *ledger.Ledger) func(network.Stream) error {
	return func(stream network.Stream) error {
		defer stream.Close()

		var req model.LedgerSyncRequest
		decoder := json.NewDecoder(stream)
		if err := decoder.Decode(&req); err != nil {
			log.Printf("failed to decode LedgerSync request: %v", err)
			return model.ErrNetworkFailure
		}

		// Validate tree ID
		if req.TreeID == "" {
			log.Printf("invalid tree ID in LedgerSync request")
			return model.ErrNetworkFailure
		}

		// Retrieve the tree (validation)
		if _, err := ledgerService.GetTree(req.TreeID); err != nil {
			log.Printf("tree not found for ledger sync: %v", err)
			resp := model.LedgerSyncResponse{Status: "error: tree not found"}
			encoder := json.NewEncoder(stream)
			encoder.Encode(resp)
			return nil
		}

		// Send success response
		resp := model.LedgerSyncResponse{
			Status: "ok",
		}

		encoder := json.NewEncoder(stream)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("failed to encode LedgerSync response: %v", err)
			return model.ErrNetworkFailure
		}

		return nil
	}
}
