package net

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"revika/internal/store"
)

// serverStreamTimeout bounds how long a single request/response exchange may
// take, so a slow or stuck peer cannot pin a stream open indefinitely.
const serverStreamTimeout = 60 * time.Second

// Server serves the shard and probe protocols for the Node role, backed by a
// content-addressed store.Store. It is the whole of a Node's behaviour: accept
// shards, return them, report possession, prove possession. Nodes are dumb and
// untrusted — the Server never decrypts, interprets, or trusts payloads; it
// only moves opaque, self-verifying blobs in and out of its store.
type Server struct {
	store store.Store
	log   *slog.Logger
}

// NewServer builds a Server over s. If log is nil, logging is discarded.
func NewServer(s store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{store: s, log: log}
}

// Register installs the Server's stream handlers on h. After this the host will
// serve /revika/shard and /revika/probe to any peer that dials them.
func (srv *Server) Register(h host.Host) {
	h.SetStreamHandler(ShardProtocol, srv.handleShard)
	h.SetStreamHandler(ProbeProtocol, srv.handleProbe)
}

// handleShard serves one shard-protocol request on s. The wire contract is one
// request/response per stream (see proto.go); we always close the stream when
// done, and Reset it on a protocol-level read failure so the peer sees the
// abort rather than a truncated reply.
func (srv *Server) handleShard(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))

	peer := s.Conn().RemotePeer()
	opByte, err := readByte(s)
	if err != nil {
		srv.log.Debug("shard: read op", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}

	ctx := context.Background()
	switch op(opByte) {
	case opPut:
		srv.handlePut(ctx, s, peer)
	case opGet:
		srv.handleGet(ctx, s, peer)
	case opHas:
		srv.handleHas(ctx, s, peer)
	case opDelete:
		srv.handleDelete(ctx, s, peer)
	default:
		srv.log.Debug("shard: unknown op", "peer", peer, "op", opByte)
		srv.replyErr(s, fmt.Errorf("unknown op %d", opByte))
	}
}

func (srv *Server) handlePut(ctx context.Context, s network.Stream, peer any) {
	data, err := readBlob(s, MaxShardSize)
	if err != nil {
		srv.log.Debug("shard put: read blob", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	id, err := srv.store.Put(ctx, data)
	if err != nil {
		srv.log.Warn("shard put: store", "peer", peer, "err", err)
		srv.replyErr(s, err)
		return
	}
	srv.log.Debug("shard put", "peer", peer, "id", id, "bytes", len(data))
	// OK + the content address the caller can verify against its own hash.
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeID(s, id)
}

func (srv *Server) handleGet(ctx context.Context, s network.Stream, peer any) {
	id, err := readID(s)
	if err != nil {
		srv.log.Debug("shard get: read id", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	data, err := srv.store.Get(ctx, id)
	if err != nil {
		srv.log.Debug("shard get: miss", "peer", peer, "id", id, "err", err)
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeBlob(s, data)
}

func (srv *Server) handleHas(ctx context.Context, s network.Stream, peer any) {
	id, err := readID(s)
	if err != nil {
		srv.log.Debug("shard has: read id", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	ok, err := srv.store.Has(ctx, id)
	if err != nil {
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	present := byte(0)
	if ok {
		present = 1
	}
	_ = writeByte(s, present)
}

func (srv *Server) handleDelete(ctx context.Context, s network.Stream, peer any) {
	id, err := readID(s)
	if err != nil {
		srv.log.Debug("shard delete: read id", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	if err := srv.store.Delete(ctx, id); err != nil {
		srv.replyErr(s, err)
		return
	}
	_ = writeByte(s, byte(statusOK))
}

// handleProbe answers a proof-of-possession challenge: given a shardID and a
// random nonce, it returns SHA-256(nonce || shardBytes). Because the nonce is
// fresh per challenge, a node cannot precompute or replay the answer — it must
// actually hold the bytes at challenge time. A verifier that also holds the
// shard (or a stored digest) can recompute and compare; the repair loop uses
// this to confirm survival without shipping the shard back.
func (srv *Server) handleProbe(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	peer := s.Conn().RemotePeer()

	id, err := readID(s)
	if err != nil {
		srv.log.Debug("probe: read id", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	nonce, err := readNonce(s)
	if err != nil {
		srv.log.Debug("probe: read nonce", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	data, err := srv.store.Get(context.Background(), id)
	if err != nil {
		srv.log.Debug("probe: miss", "peer", peer, "id", id, "err", err)
		srv.replyErr(s, err)
		return
	}
	h := sha256.New()
	h.Write(nonce)
	h.Write(data)
	proof := h.Sum(nil)
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_, _ = s.Write(proof)
}

// replyErr sends a mapped status byte, and for a generic error a short message
// blob so the client can surface it. Best-effort: a write failure here just
// means the peer went away.
func (srv *Server) replyErr(s io.Writer, err error) {
	st := errToStatus(err)
	if writeErr := writeByte(s, byte(st)); writeErr != nil {
		return
	}
	if st == statusError {
		_ = writeBlob(s, []byte(err.Error()))
	}
}
