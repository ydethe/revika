package net

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/provider"
	"revika/internal/store"
)

// RootProtocol lets a client resolve a User's current signed RootPointer by
// asking a node directly, complementing the DHT value record (root.go): a client
// that already has a node connection can fetch a root in one round-trip without a
// full DHT walk, and a node with no DHT (single-node/test setups) can still serve
// roots it knows. The node answers from its own resolver (a *Discovery GetRoot,
// i.e. its DHT view). Read-only and unauthenticated — a RootPointer is a public,
// signed, key-stripped record — so it needs no owner token. One
// request/response per stream, same framing as the shard protocol.
const RootProtocol protocol.ID = "/revika/root/1.0.0"

// maxRootReport caps the JSON a root response may occupy. A RootPointer is a
// handful of fields plus a cap whose shard list is bounded by the erasure config
// (one blob = one stripe), so 64 KiB is generous while bounding the allocation.
const maxRootReport = 64 << 10

// rootQueryTimeout bounds a single root query to a peer.
const rootQueryTimeout = 15 * time.Second

// RootResolver yields the current RootPointer for an owner. *Discovery satisfies
// it via GetRoot (resolving from the DHT). A node wires its Discovery in with
// SetRootResolver so it can answer RootProtocol queries.
type RootResolver interface {
	GetRoot(ctx context.Context, owner cap.SignPubKey) (manifest.RootPointer, bool, error)
}

// QueryRoot opens a root stream to p and resolves owner's current RootPointer.
// The request is the 32-byte owner pubkey; the server replies with a status byte
// and, on success, the JSON pointer. ok is false (nil error) when the node has no
// root for that owner. The returned pointer carries a key-stripped verify cap.
func QueryRoot(ctx context.Context, h host.Host, p peer.ID, owner cap.SignPubKey) (manifest.RootPointer, bool, error) {
	s, err := h.NewStream(ctx, p, RootProtocol)
	if err != nil {
		return manifest.RootPointer{}, false, fmt.Errorf("revika/net: open root stream to %s: %w", p, err)
	}
	defer s.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	} else {
		_ = s.SetDeadline(time.Now().Add(rootQueryTimeout))
	}
	if _, err := s.Write(owner[:]); err != nil {
		return manifest.RootPointer{}, false, fmt.Errorf("revika/net: write root query: %w", err)
	}
	if err := readResp(s); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return manifest.RootPointer{}, false, nil
		}
		return manifest.RootPointer{}, false, err
	}
	body, err := readBlob(s, maxRootReport)
	if err != nil {
		return manifest.RootPointer{}, false, fmt.Errorf("revika/net: read root record: %w", err)
	}
	rp, err := provider.DecodeRootPointer(body)
	if err != nil {
		return manifest.RootPointer{}, false, fmt.Errorf("revika/net: decode root record: %w", err)
	}
	if rp.Owner != owner || !rp.Verify() {
		return manifest.RootPointer{}, false, errors.New("revika/net: served root failed verification")
	}
	return rp, true, nil
}

// SetRootResolver attaches the resolver the node answers RootProtocol queries
// from. Call before Register; left unset, the node does not register the root
// handler at all (it advertises no root-resolution service).
func (srv *Server) SetRootResolver(r RootResolver) { srv.rootResolver = r }

// handleRoot answers one root-protocol query: it reads a 32-byte owner pubkey and
// replies with that owner's current RootPointer as JSON (status byte first,
// matching the shard protocol's framing). A miss is reported as statusNotFound so
// the client can distinguish "no such root" from a transport error.
func (srv *Server) handleRoot(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(serverStreamTimeout))
	peer := s.Conn().RemotePeer()

	var owner cap.SignPubKey
	if _, err := io.ReadFull(s, owner[:]); err != nil {
		srv.log.Debug("root: read owner", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	rp, ok, err := srv.rootResolver.GetRoot(context.Background(), owner)
	if err != nil {
		srv.log.Debug("root: resolve", "event", "root.resolve", "peer", peer, "owner", owner, "err", err)
		srv.replyErr(s, err)
		return
	}
	if !ok {
		srv.replyErr(s, store.ErrNotFound)
		return
	}
	body, err := provider.EncodeRootPointer(rp)
	if err != nil {
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeBlob(s, body)
	srv.log.Debug("root: served", "event", "root.resolve", "peer", peer, "owner", owner, "seq", rp.Seq)
}
