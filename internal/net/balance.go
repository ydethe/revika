package net

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"revika/internal/placement"
)

// BalanceProtocol carries a node's storage-load report so the diffusion
// rebalancer can compare fullness with a peer before deciding whether to shed
// shards to it (Architecture §3.4). It is read-only and unauthenticated: a load
// report reveals only aggregate counters (bytes used, capacity, shard count),
// never shard content, so it needs no owner token. One request/response per
// stream, same framing discipline as the shard protocol.
const BalanceProtocol protocol.ID = "/revika/balance/1.0.0"

// maxLoadReport caps the JSON a load response may occupy — a LoadReport is three
// integers, so a few KiB is generous while still bounding the allocation.
const maxLoadReport = 4 << 10

// balanceQueryTimeout bounds a single load query to a peer.
const balanceQueryTimeout = 15 * time.Second

// LoadReport is a node's self-declared storage load, exchanged over
// BalanceProtocol. It is a *declared* signal: a node reports its own numbers, so
// it is trusted only as far as the node is (a lying node can only mis-declare its
// own fullness, never touch another's data). Anti-Sybil/attestation of this
// signal is deferred — see Architecture §5/§10.
type LoadReport struct {
	UsedBytes     int64 `json:"used_bytes"`     // ciphertext bytes currently stored
	CapacityBytes int64 `json:"capacity_bytes"` // usable budget (min of free disk / operator quota); 0 = unknown
	Shards        int64 `json:"shards"`         // number of shards held (diagnostic; balancing uses bytes)
}

// Load projects the report onto the placement layer's normalized-load model.
func (r LoadReport) Load() placement.Load {
	return placement.Load{Used: r.UsedBytes, Capacity: r.CapacityBytes}
}

// Frac is the node's normalized fullness in [0,1] (0 when capacity is unknown).
func (r LoadReport) Frac() float64 { return r.Load().Frac() }

// FreeBytes is the remaining budget, never negative.
func (r LoadReport) FreeBytes() int64 { return r.Load().Free() }

// LoadSource yields this node's current load for the balance protocol and the
// metrics surface. It reads live state (ledger totals + a disk-capacity probe),
// so it can fail — a nil-safe caller treats an error as "capacity unknown".
type LoadSource func() (LoadReport, error)

// QueryLoad opens a balance stream to p and reads its self-declared LoadReport.
// The request carries no body: the server replies with a status byte and, on
// success, the JSON report.
func QueryLoad(ctx context.Context, h host.Host, p peer.ID) (LoadReport, error) {
	s, err := h.NewStream(ctx, p, BalanceProtocol)
	if err != nil {
		return LoadReport{}, fmt.Errorf("revika/net: open balance stream to %s: %w", p, err)
	}
	defer s.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	} else {
		_ = s.SetDeadline(time.Now().Add(balanceQueryTimeout))
	}
	if err := readResp(s); err != nil {
		return LoadReport{}, err
	}
	body, err := readBlob(s, maxLoadReport)
	if err != nil {
		return LoadReport{}, fmt.Errorf("revika/net: read load report: %w", err)
	}
	var rep LoadReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return LoadReport{}, fmt.Errorf("revika/net: decode load report: %w", err)
	}
	return rep, nil
}

// SetLoadSource attaches the node's load reporter, enabling the balance protocol
// handler to answer QueryLoad. Call before Register. Left unset, the node replies
// to load queries with an error (it advertises no capacity signal).
func (srv *Server) SetLoadSource(src LoadSource) { srv.loadSource = src }

// handleLoad answers one balance-protocol query: it reads no request body and
// replies with the node's current LoadReport as JSON (status byte first, matching
// the shard protocol's framing). A node with no load source configured fails the
// query closed rather than advertising a misleading empty report.
func (srv *Server) handleLoad(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	peer := s.Conn().RemotePeer()

	if srv.loadSource == nil {
		srv.replyErr(s, fmt.Errorf("load reporting not enabled"))
		return
	}
	rep, err := srv.loadSource()
	if err != nil {
		srv.log.Debug("balance: load source", "peer", peer, "err", err)
		srv.replyErr(s, err)
		return
	}
	body, err := json.Marshal(rep)
	if err != nil {
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeBlob(s, body)
	srv.log.Debug("balance: reported load", "event", "balance.report", "peer", peer, "frac", rep.Frac(), "shards", rep.Shards)
}
