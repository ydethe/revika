// Package kubo is the V1 IPFS adapter. It implements revika's internal/ipfs
// port by talking to an external Kubo daemon over its RPC HTTP API using the
// lightweight github.com/ipfs/go-ipfs-api Shell client.
//
// This is the ONLY package in revika permitted to import Kubo, go-cid, or
// libp2p packages (see internal/ipfs/port.go for the import invariant). All
// errors that stem from Kubo or the network are wrapped as
// model.ErrNetworkFailure so consumers never see Kubo internals.
package kubo

import (
	"context"
	"encoding/hex"
	"fmt"

	cid "github.com/ipfs/go-cid"
	shell "github.com/ipfs/go-ipfs-api"
	mh "github.com/multiformats/go-multihash"

	"github.com/revika/revika/pkg/model"
)

// Adapter implements ipfs.BlockStore, ipfs.NameService, and ipfs.PeerInfo by
// delegating to an external Kubo daemon over its RPC HTTP API.
type Adapter struct {
	sh *shell.Shell
}

// DefaultAPIAddr is the default Kubo RPC API address.
const DefaultAPIAddr = "127.0.0.1:5001"

// NewAdapter constructs a Kubo adapter targeting the given RPC API address
// (e.g. "127.0.0.1:5001"). Construction is lazy: it does not contact the
// daemon, so callers can build an adapter without a running Kubo. Reachability
// failures surface on the first network-touching call as model.ErrNetworkFailure.
func NewAdapter(apiAddr string) (*Adapter, error) {
	if apiAddr == "" {
		apiAddr = DefaultAPIAddr
	}
	sh := shell.NewShell(apiAddr)
	if sh == nil {
		return nil, fmt.Errorf("%w: could not create Kubo shell for %q", model.ErrNetworkFailure, apiAddr)
	}
	return &Adapter{sh: sh}, nil
}

// AddBlock stores raw bytes as a single-block CIDv1 (raw codec, sha2-256),
// pins the result, and returns the CID string. The multihash inside the CID is
// the sha2-256 of data, so it reconciles with model.ComputeShardID(data).
func (a *Adapter) AddBlock(ctx context.Context, data []byte) (string, error) {
	// format=raw, mhtype=sha2-256, mhlen=-1 (default length) yields a CIDv1 raw
	// block whose multihash digest equals sha2-256(data).
	c, err := a.sh.BlockPut(data, "raw", "sha2-256", -1)
	if err != nil {
		return "", fmt.Errorf("%w: block put failed", model.ErrNetworkFailure)
	}
	if err := a.sh.Pin(c); err != nil {
		return "", fmt.Errorf("%w: pin failed", model.ErrNetworkFailure)
	}
	return c, nil
}

// GetBlock fetches block bytes by CID string.
func (a *Adapter) GetBlock(ctx context.Context, c string) ([]byte, error) {
	data, err := a.sh.BlockGet(c)
	if err != nil {
		return nil, fmt.Errorf("%w: block get failed", model.ErrNetworkFailure)
	}
	return data, nil
}

// Pin pins an existing CID locally.
func (a *Adapter) Pin(ctx context.Context, c string) error {
	if err := a.sh.Pin(c); err != nil {
		return fmt.Errorf("%w: pin failed", model.ErrNetworkFailure)
	}
	return nil
}

// Provide advertises the CID to the DHT so other peers can find it. It is
// best-effort and uses the Kubo "routing/provide" RPC path.
func (a *Adapter) Provide(ctx context.Context, c string) error {
	if err := a.sh.Request("routing/provide", c).Exec(ctx, nil); err != nil {
		return fmt.Errorf("%w: provide failed", model.ErrNetworkFailure)
	}
	return nil
}

// PublishIPNS publishes a value CID under this node's IPNS key and returns the
// IPNS name.
func (a *Adapter) PublishIPNS(ctx context.Context, valueCID string) (string, error) {
	resp, err := a.sh.PublishWithDetails(valueCID, "", 0, 0, false)
	if err != nil {
		return "", fmt.Errorf("%w: ipns publish failed", model.ErrNetworkFailure)
	}
	return resp.Name, nil
}

// ResolveIPNS resolves an IPNS name to its current value CID.
func (a *Adapter) ResolveIPNS(ctx context.Context, name string) (string, error) {
	valueCID, err := a.sh.Resolve(name)
	if err != nil {
		return "", fmt.Errorf("%w: ipns resolve failed", model.ErrNetworkFailure)
	}
	return valueCID, nil
}

// ID returns this node's IPFS peer ID.
func (a *Adapter) ID(ctx context.Context) (string, error) {
	out, err := a.sh.ID()
	if err != nil {
		return "", fmt.Errorf("%w: id failed", model.ErrNetworkFailure)
	}
	return out.ID, nil
}

// Peers returns the peer IDs this node is currently connected to.
func (a *Adapter) Peers(ctx context.Context) ([]string, error) {
	conns, err := a.sh.SwarmPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: swarm peers failed", model.ErrNetworkFailure)
	}
	peers := make([]string, 0, len(conns.Peers))
	for _, p := range conns.Peers {
		peers = append(peers, p.Peer)
	}
	return peers, nil
}

// Connect connects to a peer by multiaddr.
func (a *Adapter) Connect(ctx context.Context, multiaddr string) error {
	if err := a.sh.SwarmConnect(ctx, multiaddr); err != nil {
		return fmt.Errorf("%w: swarm connect failed", model.ErrNetworkFailure)
	}
	return nil
}

// ExpectedCID computes the CIDv1 (raw codec, sha2-256) that AddBlock is
// expected to return for the given bytes. Used to assert AddBlock's contract.
func ExpectedCID(data []byte) (string, error) {
	mhash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("%w: multihash failed", model.ErrNetworkFailure)
	}
	return cid.NewCidV1(cid.Raw, mhash).String(), nil
}

// CIDMatchesSHA256 reports whether the given CID's multihash is a sha2-256
// digest equal to the provided sha2-256 hex string (e.g. from
// model.ComputeShardID). Returns false if the CID uses a different hash.
func CIDMatchesSHA256(cidStr, sha256Hex string) (bool, error) {
	c, err := cid.Decode(cidStr)
	if err != nil {
		return false, fmt.Errorf("%w: cid decode failed", model.ErrNetworkFailure)
	}
	decoded, err := mh.Decode(c.Hash())
	if err != nil {
		return false, fmt.Errorf("%w: multihash decode failed", model.ErrNetworkFailure)
	}
	if decoded.Code != mh.SHA2_256 {
		return false, nil
	}
	return hex.EncodeToString(decoded.Digest) == sha256Hex, nil
}
