//go:build v2direct

package network

import (
	"github.com/libp2p/go-libp2p/core/protocol"
)

// Protocol IDs for Revika's libp2p-based protocols.
const (
	ProtoPutShard   protocol.ID = "/revika/1.0/put-shard"
	ProtoGetShard   protocol.ID = "/revika/1.0/get-shard"
	ProtoLedgerSync protocol.ID = "/revika/1.0/ledger-sync"
	ProtoShare      protocol.ID = "/revika/1.0/share"
	ProtoRevoke     protocol.ID = "/revika/1.0/revoke"
)

// MessageRouter routes incoming streams to appropriate handler.
// Each protocol has a registered handler function.
type MessageRouter struct {
	registry *HandlerRegistry
}

// NewMessageRouter creates a new message router.
func NewMessageRouter() *MessageRouter {
	return &MessageRouter{
		registry: NewHandlerRegistry(),
	}
}

// RegisterHandler registers a handler for a protocol.
func (r *MessageRouter) RegisterHandler(protocolID protocol.ID, handler StreamHandler) {
	r.registry.Register(string(protocolID), handler)
}

// RouteStream routes an incoming stream to the appropriate handler.
// If no handler is registered, an error is returned.
func (r *MessageRouter) RouteStream(protocolID protocol.ID, stream StreamHandler) (StreamHandler, bool) {
	return r.registry.Get(string(protocolID))
}

// GetRegisteredProtocols returns all registered protocol IDs.
func (r *MessageRouter) GetRegisteredProtocols() []protocol.ID {
	protocolIDs := []protocol.ID{
		ProtoPutShard,
		ProtoGetShard,
		ProtoLedgerSync,
		ProtoShare,
		ProtoRevoke,
	}
	return protocolIDs
}
