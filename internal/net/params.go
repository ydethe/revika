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

	"revika/internal/cap"
)

// ParamsProtocol lets a client learn a node's admission policy up front instead
// of discovering it as a late ErrUnauthorized on a failed PUT. Today it carries
// the proof-of-work policy (puzzle + difficulty) so `revika-ctl connect` can mint
// an owner identity the node will accept without the operator re-typing the
// policy; the NodeParams envelope leaves room to advertise more (e.g. suggested
// erasure k/m) without a protocol bump. Read-only and unauthenticated — it
// reveals only the node's own local policy, never shard content — so it needs no
// owner token. One request/response per stream, same framing as the shard
// protocol.
const ParamsProtocol protocol.ID = "/revika/params/1.0.0"

// maxParamsReport caps the JSON a params response may occupy — a NodeParams is a
// handful of small fields, so a few KiB is generous while bounding the allocation.
const maxParamsReport = 4 << 10

// paramsQueryTimeout bounds a single params query to a peer.
const paramsQueryTimeout = 15 * time.Second

// NodeParams is a node's self-declared admission policy, exchanged over
// ParamsProtocol. It is a *declared* signal, trusted only as far as the node is:
// a lying node can only mis-declare its own policy (which at worst makes a client
// mint a needlessly-hard or too-easy identity — the node still re-checks every
// PUT against its real policy in enforcePoW), never touch another's data.
type NodeParams struct {
	PoW PoWInfo `json:"pow"` // proof-of-work admission policy this node enforces on writes
}

// QueryParams opens a params stream to p and reads its self-declared NodeParams.
// The request carries no body: the server replies with a status byte and, on
// success, the JSON params.
func QueryParams(ctx context.Context, h host.Host, p peer.ID) (NodeParams, error) {
	s, err := h.NewStream(ctx, p, ParamsProtocol)
	if err != nil {
		return NodeParams{}, fmt.Errorf("revika/net: open params stream to %s: %w", p, err)
	}
	defer s.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	} else {
		_ = s.SetDeadline(time.Now().Add(paramsQueryTimeout))
	}
	if err := readResp(s); err != nil {
		return NodeParams{}, err
	}
	body, err := readBlob(s, maxParamsReport)
	if err != nil {
		return NodeParams{}, fmt.Errorf("revika/net: read node params: %w", err)
	}
	var np NodeParams
	if err := json.Unmarshal(body, &np); err != nil {
		return NodeParams{}, fmt.Errorf("revika/net: decode node params: %w", err)
	}
	return np, nil
}

// powInfo projects the server's proof-of-work admission policy onto the wire
// PoWInfo, matching MetricsServer.SetPoW's semantics: a zero minimum difficulty
// means admission is disabled, so no puzzle is reported.
func (srv *Server) powInfo() PoWInfo {
	if srv.powMin == 0 {
		return PoWInfo{}
	}
	// Advertise the canonical short name PuzzleByName accepts (not Puzzle.Name(),
	// which carries unparseable parameters) so the client re-derives this puzzle.
	return PoWInfo{Enabled: true, Puzzle: cap.PuzzleName(srv.powPuzzle), Difficulty: uint(srv.powMin)}
}

// handleParams answers one params-protocol query: it reads no request body and
// replies with the node's NodeParams as JSON (status byte first, matching the
// shard protocol's framing). The policy is read directly from the Server; it is
// set once via SetPoW before Register and not mutated afterwards.
func (srv *Server) handleParams(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	peer := s.Conn().RemotePeer()

	body, err := json.Marshal(NodeParams{PoW: srv.powInfo()})
	if err != nil {
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeBlob(s, body)
	srv.log.Debug("params: reported policy", "event", "params.report", "peer", peer, "pow", srv.powMin)
}
