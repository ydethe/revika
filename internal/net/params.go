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

// FetchPoWPolicy dials each bootstrap peer directly — their multiaddrs already
// carry /p2p/<id>, so no DHT warm-up is needed — reads each node's self-declared
// admission policy over ParamsProtocol, and reconciles them into the single
// strictest requirement a new participant must satisfy. Because one participant
// faces the whole reachable set, it takes the max difficulty and — since one
// self-certifying identity only verifies against a single puzzle — rejects a set
// whose PoW-enforcing nodes disagree on the puzzle. It fails when no bootstrap
// node answers, so an adopted policy always matches a live node rather than an
// offline guess. The caller supplies the host so its connection pool is reused;
// dialTimeout bounds each peer's connect+query. It returns an empty puzzle and
// zero difficulty when every reachable node enforces no PoW.
//
// Both `revika-ctl connect` (to mint an admissible identity) and a joining
// revika-node (to inherit its bootstrap peers' admission bar) drive it, so the
// two learn the network's policy through one code path.
func FetchPoWPolicy(ctx context.Context, h host.Host, bootstrap []string, dialTimeout time.Duration) (puzzle string, difficulty uint, err error) {
	var (
		reached int
		lastErr error
	)
	for _, addr := range bootstrap {
		info, aerr := peer.AddrInfoFromString(addr)
		if aerr != nil {
			return "", 0, fmt.Errorf("invalid bootstrap address %q: %w", addr, aerr)
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
		if !np.PoW.Enabled {
			continue // node enforces no PoW; leaves difficulty 0
		}
		if puzzle == "" {
			puzzle = np.PoW.Puzzle
		} else if np.PoW.Puzzle != puzzle {
			return "", 0, fmt.Errorf("bootstrap nodes disagree on proof-of-work puzzle (%q vs %q); one identity cannot satisfy both — connect to a consistent node set", puzzle, np.PoW.Puzzle)
		}
		if np.PoW.Difficulty > difficulty {
			difficulty = np.PoW.Difficulty
		}
	}
	if reached == 0 {
		if lastErr != nil {
			return "", 0, fmt.Errorf("could not reach any bootstrap node (%s): %w", strings.Join(bootstrap, ", "), lastErr)
		}
		return "", 0, fmt.Errorf("could not reach any bootstrap node (%s)", strings.Join(bootstrap, ", "))
	}
	return puzzle, difficulty, nil
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
