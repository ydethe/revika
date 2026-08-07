package net

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// ParamsProtocol lets a client learn a node's admission policy up front instead
// of discovering it as a late ErrUnauthorized on a failed PUT. Today it carries
// the proof-of-work difficulty so `revika-ctl connect` can mint an owner
// identity the node will accept without the operator re-typing the
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
	// Repair and Rebalance are the maintenance schedule the node runs; a joining
	// node inherits them (§3.4) the same way it inherits PoW, so a fresh node need
	// only know a bootstrap peer to adopt the cluster's repair/rebalance cadence.
	// Added after PoW; older nodes omit them and a joiner reads the zero value
	// (not running) — the JSON envelope stays forward-compatible without a bump.
	Repair    RepairInfo    `json:"repair"`
	Rebalance RebalanceInfo `json:"rebalance"`
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

// FetchNodePolicy dials each bootstrap peer directly — their multiaddrs already
// carry /p2p/<id>, so no DHT warm-up is needed — reads each node's self-declared
// NodeParams over ParamsProtocol, and reconciles them into the single policy a
// new participant should adopt. Because one participant faces the whole reachable
// set it reconciles conservatively:
//
//   - PoW: strictest wins. Max difficulty. The puzzle is always Argon2id, so
//     there is nothing to reconcile beyond the difficulty.
//   - Repair / Rebalance: any-enabled and most-aggressive. If any reachable node
//     runs the loop the joiner runs it too, at the shortest advertised interval
//     (and, for rebalance, the smallest threshold) — so a joiner never dilutes the
//     cluster's maintenance cadence below what an existing node already keeps.
//
// It fails when no bootstrap node answers, so an adopted policy always matches a
// live node rather than an offline guess. The caller supplies the host so its
// connection pool is reused; dialTimeout bounds each peer's connect+query. A
// reachable set that enforces no PoW and runs no maintenance yields the zero
// NodeParams.
//
// Both `revika-ctl connect` (which needs only .PoW, to mint an admissible
// identity) and a joining revika-node (which adopts the whole policy — admission
// bar plus maintenance schedule) drive it, so the two learn the network's policy
// through one code path.
func FetchNodePolicy(ctx context.Context, h host.Host, bootstrap []string, dialTimeout time.Duration) (NodeParams, error) {
	var (
		out        NodeParams
		haveThresh bool
		reached    int
		lastErr    error
	)
	for _, addr := range bootstrap {
		info, aerr := peer.AddrInfoFromString(addr)
		if aerr != nil {
			return NodeParams{}, fmt.Errorf("invalid bootstrap address %q: %w", addr, aerr)
		}
		cctx, cancel := context.WithTimeout(ctx, dialTimeout)
		if cerr := Connect(cctx, h, *info); cerr != nil {
			cancel()
			lastErr = cerr
			continue
		}
		np, qerr := QueryParams(cctx, h, info.ID)
		cancel()
		if qerr != nil {
			lastErr = qerr
			continue
		}
		reached++

		// PoW: strictest wins (max difficulty; the puzzle is always Argon2id).
		if np.PoW.Enabled && np.PoW.Difficulty > out.PoW.Difficulty {
			out.PoW.Difficulty = np.PoW.Difficulty
		}

		// Repair: any-enabled + shortest interval.
		if np.Repair.Enabled {
			out.Repair.Enabled = true
			if np.Repair.Interval > 0 && (out.Repair.Interval == 0 || np.Repair.Interval < out.Repair.Interval) {
				out.Repair.Interval = np.Repair.Interval
			}
		}

		// Rebalance: any-enabled + shortest interval + smallest threshold (0 is a
		// valid "no dead-band" policy, so track it with haveThresh rather than a
		// zero sentinel).
		if np.Rebalance.Enabled {
			out.Rebalance.Enabled = true
			if np.Rebalance.Interval > 0 && (out.Rebalance.Interval == 0 || np.Rebalance.Interval < out.Rebalance.Interval) {
				out.Rebalance.Interval = np.Rebalance.Interval
			}
			if !haveThresh || np.Rebalance.Threshold < out.Rebalance.Threshold {
				out.Rebalance.Threshold = np.Rebalance.Threshold
				haveThresh = true
			}
		}
	}
	if reached == 0 {
		if lastErr != nil {
			return NodeParams{}, fmt.Errorf("could not reach any bootstrap node (%s): %w", strings.Join(bootstrap, ", "), lastErr)
		}
		return NodeParams{}, fmt.Errorf("could not reach any bootstrap node (%s)", strings.Join(bootstrap, ", "))
	}
	out.PoW.Enabled = out.PoW.Difficulty > 0
	return out, nil
}

// powInfo projects the server's proof-of-work admission policy onto the wire
// PoWInfo, matching MetricsServer.SetPoW's semantics: a zero minimum difficulty
// means admission is disabled.
func (srv *Server) powInfo() PoWInfo {
	if srv.powMin == 0 {
		return PoWInfo{}
	}
	return PoWInfo{Enabled: true, Difficulty: uint(srv.powMin)}
}

// handleParams answers one params-protocol query: it reads no request body and
// replies with the node's NodeParams as JSON (status byte first, matching the
// shard protocol's framing). The policy is read directly from the Server; it is
// set once (SetPoW + SetMaintenancePolicy) before Register and not mutated
// afterwards.
func (srv *Server) handleParams(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	peer := s.Conn().RemotePeer()

	body, err := json.Marshal(NodeParams{
		PoW:       srv.powInfo(),
		Repair:    srv.repairPolicy,
		Rebalance: srv.rebalancePolicy,
	})
	if err != nil {
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeBlob(s, body)
	srv.log.Debug("params: reported policy", "event", "params.report", "peer", peer,
		"pow", srv.powMin, "repair", srv.repairPolicy.Enabled, "rebalance", srv.rebalancePolicy.Enabled)
}
