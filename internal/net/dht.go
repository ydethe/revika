package net

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	discutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multihash"

	"revika/internal/store"
)

// revikaDHTPrefix isolates revika's Kademlia network from the public IPFS DHT:
// the DHT stream protocol becomes /revika/kad/1.0.0, so revika peers only ever
// exchange routing state and provider records with other revika peers. This is
// revika's *own* serverless network, not a corner of IPFS.
const revikaDHTPrefix protocol.ID = "/revika"

// storageNamespace is the rendezvous string nodes advertise themselves under, so
// a client can discover storage nodes with no central registry — it asks the
// DHT "who is providing this namespace?" the same way it asks who holds a shard.
const storageNamespace = "revika/storage/1.0.0"

// provideTimeout bounds a single provider-record publish (Provide fans out to
// the peers closest to the key and can take a while on a large network).
const provideTimeout = 60 * time.Second

// DHTMode selects how a host participates in the Kademlia DHT.
type DHTMode int

const (
	// DHTModeAuto becomes a server when libp2p judges the host publicly
	// reachable, else a client. Sensible default for a dual-role machine.
	DHTModeAuto DHTMode = iota
	// DHTModeClient queries the DHT but never stores records for others — for
	// ephemeral, NAT'd, or short-lived peers such as the CLI client.
	DHTModeClient
	// DHTModeServer is a full participant: it answers queries and stores routing
	// state and provider records. The mode a Node runs in.
	DHTModeServer
)

func (m DHTMode) libp2p() dht.ModeOpt {
	switch m {
	case DHTModeClient:
		return dht.ModeClient
	case DHTModeServer:
		return dht.ModeServer
	default:
		return dht.ModeAuto
	}
}

// DiscoveryConfig configures the DHT layer.
type DiscoveryConfig struct {
	Mode      DHTMode
	Bootstrap []string // multiaddrs (with /p2p/<id>) of peers to join through
	Log       *slog.Logger
}

// Discovery is revika's Kademlia DHT layer: serverless peer, node-service, and
// content (shard-provider) discovery. It is what lets a client find who holds a
// shard, and lets nodes find one another, with no central server — only a
// bootstrap peer to get in, after which the self-organising DHT takes over.
//
// Defence controls (security/Defence.md; primitive P15 in security/frameworks.md):
//   SC-36 (Distributed Processing and Storage) — the /revika Kademlia DHT gives redundant,
//         serverless discovery of shard providers and peers, with no single point.
type Discovery struct {
	h   host.Host
	dht *dht.IpfsDHT
	rd  *drouting.RoutingDiscovery
	log *slog.Logger

	// seen tracks peer IDs already reported by noteDiscovered so each node is
	// logged only the first time this Discovery hears about it — DHT lookups are
	// polled and repeatedly return the same peers.
	mu   sync.Mutex
	seen map[peer.ID]struct{}
}

// NewDiscovery builds the DHT over h, connects to the configured bootstrap
// peers, and kicks off the routing-table bootstrap. The caller owns the result
// and must Close it before closing h.
func NewDiscovery(ctx context.Context, h host.Host, cfg DiscoveryConfig) (*Discovery, error) {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	kad, err := dht.New(h, dht.Mode(cfg.Mode.libp2p()), dht.ProtocolPrefix(revikaDHTPrefix))
	if err != nil {
		return nil, fmt.Errorf("revika/net: new dht: %w", err)
	}
	d := &Discovery{h: h, dht: kad, rd: drouting.NewRoutingDiscovery(kad), log: log, seen: map[peer.ID]struct{}{}}
	if err := d.Bootstrap(ctx, cfg.Bootstrap); err != nil {
		_ = kad.Close()
		return nil, err
	}
	return d, nil
}

// Bootstrap connects to the given bootstrap peers (best-effort: a peer that
// fails to dial is logged and skipped) and refreshes the DHT routing table. If
// bootstrap peers are supplied but none can be reached, it returns an error — a
// peer that cannot reach the network is a hard failure worth surfacing.
func (d *Discovery) Bootstrap(ctx context.Context, peers []string) error {
	var connected int
	for _, addr := range peers {
		pi, err := peer.AddrInfoFromString(addr)
		if err != nil {
			d.log.Warn("dht: skipping bad bootstrap addr", "addr", addr, "err", err)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, connectTimeout)
		err = d.h.Connect(cctx, *pi)
		cancel()
		if err != nil {
			d.log.Warn("dht: bootstrap connect failed", "peer", pi.ID, "err", err)
			continue
		}
		connected++
		d.log.Debug("dht: bootstrapped via peer", "peer", pi.ID)
	}
	if len(peers) > 0 && connected == 0 {
		return fmt.Errorf("revika/net: could not reach any of %d bootstrap peer(s)", len(peers))
	}
	if err := d.dht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("revika/net: dht bootstrap: %w", err)
	}
	return nil
}

// shardCID maps a shard's content address to the CID used as its DHT provider
// key. The ShardID is already a SHA-256 digest, so we wrap it as a SHA2-256
// multihash under a CIDv1 raw codec: a stable, unique key per shard.
func shardCID(id store.ShardID) (cid.Cid, error) {
	mh, err := multihash.Encode(id[:], multihash.SHA2_256)
	if err != nil {
		return cid.Undef, fmt.Errorf("revika/net: shard multihash: %w", err)
	}
	return cid.NewCidV1(cid.Raw, mh), nil
}

// Announce publishes a provider record for id: "this host holds this shard".
func (d *Discovery) Announce(ctx context.Context, id store.ShardID) error {
	c, err := shardCID(id)
	if err != nil {
		return err
	}
	if err := d.dht.Provide(ctx, c, true); err != nil {
		return fmt.Errorf("revika/net: announce %s: %w", id, err)
	}
	return nil
}

// ProvideAll re-announces every id, best-effort: individual failures are logged
// and do not stop the batch. A Node uses this for startup and periodic reprovide
// of the shards it holds (provider records expire, so they must be refreshed).
func (d *Discovery) ProvideAll(ctx context.Context, ids []store.ShardID) {
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		actx, cancel := context.WithTimeout(ctx, provideTimeout)
		if err := d.Announce(actx, id); err != nil {
			d.log.Debug("dht: reprovide failed", "shard", id, "err", err)
		}
		cancel()
	}
}

// noteDiscovered logs each peer in pis the first time this Discovery encounters
// it, tagged with the channel (via) it was found through. Repeated sightings —
// every polled lookup returns the same peers — are silent, so the log carries
// exactly one line per genuinely new node.
func (d *Discovery) noteDiscovered(pis []peer.AddrInfo, via string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, pi := range pis {
		if _, ok := d.seen[pi.ID]; ok {
			continue
		}
		d.seen[pi.ID] = struct{}{}
		d.log.Info("discovered node", "peer", pi.ID, "via", via, "addrs", pi.Addrs)
	}
}

// FindProviders returns peers that have announced a provider record for id,
// capped at max (a default is used if max <= 0). The local host is excluded.
func (d *Discovery) FindProviders(ctx context.Context, id store.ShardID, max int) ([]peer.AddrInfo, error) {
	if max <= 0 {
		max = 20
	}
	c, err := shardCID(id)
	if err != nil {
		return nil, err
	}
	var out []peer.AddrInfo
	for pi := range d.dht.FindProvidersAsync(ctx, c, max) {
		if pi.ID == d.h.ID() {
			continue
		}
		out = append(out, pi)
	}
	d.noteDiscovered(out, "dht/provider")
	return out, nil
}

// AdvertiseLoop persistently advertises this host as a revika storage node under
// the well-known namespace, re-advertising before each record lapses. It returns
// immediately; the loop runs in the background until ctx is cancelled.
func (d *Discovery) AdvertiseLoop(ctx context.Context) {
	discutil.Advertise(ctx, d.rd, storageNamespace)
}

// FindNodes discovers storage nodes that have advertised themselves, up to
// limit. These are the candidate targets for placing shards. The local host is
// excluded.
func (d *Discovery) FindNodes(ctx context.Context, limit int) ([]peer.AddrInfo, error) {
	if limit <= 0 {
		limit = 20
	}
	peers, err := discutil.FindPeers(ctx, d.rd, storageNamespace, discovery.Limit(limit))
	if err != nil {
		return nil, fmt.Errorf("revika/net: find nodes: %w", err)
	}
	out := peers[:0]
	for _, pi := range peers {
		if pi.ID == d.h.ID() {
			continue
		}
		out = append(out, pi)
	}
	d.noteDiscovered(out, "dht/storage")
	return out, nil
}

// RoutingTableSize reports how many peers are in the DHT routing table — a rough
// health signal (0 means we are effectively alone / not yet bootstrapped).
func (d *Discovery) RoutingTableSize() int { return d.dht.RoutingTable().Size() }

// WaitReady blocks until the DHT routing table holds at least one peer — so
// queries can actually be routed — or ctx is done. Bootstrap populates the table
// asynchronously (only after peers complete the identify handshake), so a caller
// that queries immediately after NewDiscovery would otherwise race an empty
// table and get no results. Returns an error if the table never became ready.
func (d *Discovery) WaitReady(ctx context.Context) error {
	if d.RoutingTableSize() > 0 {
		return nil
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("revika/net: DHT routing table not ready: %w", ctx.Err())
		case <-ticker.C:
			if d.RoutingTableSize() > 0 {
				return nil
			}
		}
	}
}

// Close shuts down the DHT. Call before closing the underlying host.
func (d *Discovery) Close() error { return d.dht.Close() }
