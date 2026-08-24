//go:build v2direct

package network

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/revika/revika/pkg/model"
)

// NetworkType represents the network configuration mode.
type NetworkType string

const (
	NetworkPublic  NetworkType = "Public"
	NetworkHybrid  NetworkType = "Hybrid"
	NetworkPrivate NetworkType = "Private"
)

// Host wraps libp2p.Host and manages protocols.
type Host struct {
	h       host.Host
	dht     *dht.IpfsDHT
	netType NetworkType
	router  *MessageRouter
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewHost creates and initializes a libp2p host with the specified network type.
// Returns model.ErrNetworkFailure if host creation or discovery setup fails.
func NewHost(ctx context.Context, networkType NetworkType) (*Host, error) {
	// Create a derived context for lifecycle management
	hostCtx, cancel := context.WithCancel(ctx)

	// Create libp2p host with default security and transport options
	h, err := libp2p.New(
		libp2p.DefaultSecurity,
		libp2p.DefaultMuxers,
		libp2p.DefaultTransports,
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: failed to create libp2p host", model.ErrNetworkFailure)
	}

	var dhtInstance *dht.IpfsDHT

	// Bootstrap DHT for public and hybrid networks
	if networkType != NetworkPrivate {
		dhtInstance, err = dht.New(hostCtx, h)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("%w: failed to create DHT", model.ErrNetworkFailure)
		}
	}

	hostObj := &Host{
		h:       h,
		dht:     dhtInstance,
		netType: networkType,
		router:  NewMessageRouter(),
		ctx:     hostCtx,
		cancel:  cancel,
	}

	return hostObj, nil
}

// ID returns the peer ID of this host as a string.
func (h *Host) ID() string {
	return h.h.ID().String()
}

// Connect connects to a known peer by address.
// Returns model.ErrNetworkFailure if the connection fails.
// The peerAddr should be in the format "/ip4/.../tcp/.../p2p/<peer-id>"
func (h *Host) Connect(ctx context.Context, peerAddr string) error {
	info, err := peer.AddrInfoFromString(peerAddr)
	if err != nil {
		return fmt.Errorf("%w: invalid peer address", model.ErrNetworkFailure)
	}

	if err := h.h.Connect(ctx, *info); err != nil {
		return fmt.Errorf("%w: failed to connect to peer", model.ErrNetworkFailure)
	}

	return nil
}

// RegisterProtocol registers a protocol handler for the specified protocol ID.
func (h *Host) RegisterProtocol(pid protocol.ID, handler StreamHandler) {
	h.router.RegisterHandler(pid, handler)
	h.h.SetStreamHandler(pid, handler)
}

// Close gracefully closes the host and all related services.
func (h *Host) Close() error {
	h.cancel()

	if h.dht != nil {
		if err := h.dht.Close(); err != nil {
			// Log but don't fail; best effort
			_ = err
		}
	}

	if err := h.h.Close(); err != nil {
		return fmt.Errorf("failed to close libp2p host: %w", err)
	}

	return nil
}

// GetPeers returns list of connected peer IDs.
func (h *Host) GetPeers() ([]string, error) {
	peerIDs := h.h.Network().Peers()
	peers := make([]string, 0, len(peerIDs))

	for _, peerID := range peerIDs {
		peers = append(peers, peerID.String())
	}

	return peers, nil
}

// GetNetworkType returns the configured network type.
func (h *Host) GetNetworkType() NetworkType {
	return h.netType
}

// GetRouter returns the message router for this host.
func (h *Host) GetRouter() *MessageRouter {
	return h.router
}
