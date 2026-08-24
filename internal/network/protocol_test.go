//go:build v2direct

package network

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
)

func TestMessageRouter_RegisterHandler(t *testing.T) {
	router := NewMessageRouter()

	testHandler := func(stream network.Stream) error {
		return nil
	}

	router.RegisterHandler(ProtoPutShard, testHandler)

	handler, exists := router.registry.Get(string(ProtoPutShard))
	if !exists {
		t.Errorf("handler not registered")
	}
	if handler == nil {
		t.Errorf("expected non-nil handler")
	}
}

func TestMessageRouter_GetRegisteredProtocols(t *testing.T) {
	router := NewMessageRouter()

	protocols := router.GetRegisteredProtocols()
	if len(protocols) != 5 {
		t.Errorf("expected 5 protocols, got %d", len(protocols))
	}

	protocolMap := make(map[string]bool)
	for _, p := range protocols {
		protocolMap[string(p)] = true
	}

	expectedProtocols := []string{
		string(ProtoPutShard),
		string(ProtoGetShard),
		string(ProtoLedgerSync),
		string(ProtoShare),
		string(ProtoRevoke),
	}

	for _, expected := range expectedProtocols {
		if !protocolMap[expected] {
			t.Errorf("expected protocol %s not found", expected)
		}
	}
}

func TestHandlerRegistry_Register_And_Get(t *testing.T) {
	registry := NewHandlerRegistry()

	testHandler := func(stream network.Stream) error {
		return nil
	}

	registry.Register("test-proto", testHandler)

	handler, exists := registry.Get("test-proto")
	if !exists {
		t.Errorf("handler not found after registration")
	}
	if handler == nil {
		t.Errorf("expected non-nil handler")
	}
}

func TestHandlerRegistry_Get_NotFound(t *testing.T) {
	registry := NewHandlerRegistry()

	handler, exists := registry.Get("nonexistent")
	if exists {
		t.Errorf("expected handler not found, but it was")
	}
	if handler != nil {
		t.Errorf("expected nil handler for nonexistent protocol")
	}
}

func TestHandlerRegistry_Multiple_Handlers(t *testing.T) {
	registry := NewHandlerRegistry()

	handler1 := func(stream network.Stream) error { return nil }
	handler2 := func(stream network.Stream) error { return nil }
	handler3 := func(stream network.Stream) error { return nil }

	registry.Register("proto1", handler1)
	registry.Register("proto2", handler2)
	registry.Register("proto3", handler3)

	if len(registry.handlers) != 3 {
		t.Errorf("expected 3 handlers, got %d", len(registry.handlers))
	}

	for i, proto := range []string{"proto1", "proto2", "proto3"} {
		handler, exists := registry.Get(proto)
		if !exists {
			t.Errorf("handler %d not found", i+1)
		}
		if handler == nil {
			t.Errorf("expected non-nil handler %d", i+1)
		}
	}
}
