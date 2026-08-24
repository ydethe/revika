//go:build v2direct

package network

import (
	"github.com/libp2p/go-libp2p/core/network"
)

// StreamHandler is a function type that handles an incoming libp2p stream.
type StreamHandler func(stream network.Stream) error

// HandlerRegistry holds registered protocol handlers.
type HandlerRegistry struct {
	handlers map[string]StreamHandler
}

// NewHandlerRegistry creates an empty handler registry.
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		handlers: make(map[string]StreamHandler),
	}
}

// Register adds a handler for a protocol.
func (r *HandlerRegistry) Register(protocol string, handler StreamHandler) {
	r.handlers[protocol] = handler
}

// Get retrieves a handler for a protocol.
func (r *HandlerRegistry) Get(protocol string) (StreamHandler, bool) {
	handler, exists := r.handlers[protocol]
	return handler, exists
}
