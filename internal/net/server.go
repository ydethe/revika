package net

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
	"revika/internal/stripe"
)

// serverStreamTimeout bounds how long a single request/response exchange may
// take, so a slow or stuck peer cannot pin a stream open indefinitely.
const serverStreamTimeout = 60 * time.Second

// Server serves the shard and probe protocols for the Node role, backed by a
// content-addressed store.Store. It is the whole of a Node's behaviour: accept
// shards, return them, report possession, prove possession. Nodes are dumb and
// untrusted — the Server never decrypts, interprets, or trusts payloads; it
// only moves opaque, self-verifying blobs in and out of its store.
//
// Defence controls (security/Defence.md; primitives P23, P20, P9, P14, P18 in
// security/frameworks.md) — the enforcement points the Node runs on writes/probes:
//
//	SA-8  (Security and Privacy Engineering Principles) — the node never decrypts or trusts
//	      payloads; security does not depend on node good behaviour.
//	AC-3  (Access Enforcement)          — PUT/DELETE require a signed owner token or a valid repair grant.
//	SC-5  (Denial-of-Service Protection) — proof-of-work admission (enforcePoW) gates fresh owner writes.
//	SI-7  (…Information Integrity)        — handleProbe answers fresh-nonce possession challenges.
//	SI-10 (Information Input Validation)  — unknown ops and unauthorized writes fail closed.
type Server struct {
	store     store.Store
	log       *slog.Logger
	announcer Announcer
	ledger    *ledger.Ledger

	// Proof-of-work admission policy. When powMin > 0, an owner identity
	// presented on a write must satisfy powMin leading zero bits under powPuzzle,
	// or the write is refused — raising the cost of minting a fresh identity to
	// replace a banned one (see internal/cap/pow.go). Zero disables the check.
	powPuzzle cap.Puzzle
	powMin    cap.Difficulty

	// loadSource, when set, reports this node's storage load for the balance
	// protocol (Architecture §3.4). Left nil, the node answers load queries with
	// an error — it advertises no capacity signal and neither attracts nor sheds
	// shards via rebalancing.
	loadSource LoadSource
}

// Announcer publishes a DHT provider record announcing that this node holds a
// shard. *Discovery satisfies it. When a Server has an announcer set (via
// SetAnnouncer), it announces every shard it accepts on Put, so stored shards
// become discoverable across the network.
type Announcer interface {
	Announce(ctx context.Context, id store.ShardID) error
}

// NewServer builds a Server over s. If log is nil, logging is discarded.
func NewServer(s store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{store: s, log: log}
}

// SetAnnouncer attaches a DHT announcer so accepted shards are advertised as
// provider records. Call before Register; safe to leave unset for a node that
// does not participate in the DHT.
func (srv *Server) SetAnnouncer(a Announcer) { srv.announcer = a }

// SetLedger attaches an ownership/quota ledger. Call before Register. When set,
// the server enforces authorization on PUT/DELETE (a valid signed token is
// required, DELETE only drops the caller's own claim, and PUT is quota-checked).
// Left unset, the server behaves as an unauthenticated blob store — the mode
// used by in-memory tests and legacy single-node setups.
func (srv *Server) SetLedger(l *ledger.Ledger) { srv.ledger = l }

// SetPoW sets the proof-of-work admission policy for writes: the owner identity
// (the Ed25519 pubkey recovered from a PUT's auth token) must be self-certifying
// — its puzzle digest must have at least d leading zero bits — or the write is
// refused with ErrUnauthorized. This is what makes an identity ban bite:
// replacing a banned owner costs ~2^d puzzle evaluations, not milliseconds.
// difficulty and puzzle are local operator policy; a client must mint (revika-ctl
// keygen) with a matching puzzle and difficulty >= d, since a self-certifying key
// only verifies against the exact puzzle it was minted for. The grant-authorized
// repair path is exempt (it regenerates already-admitted data, and repair is
// mandatory), as is DELETE (owner-scoped; drops only the caller's own claim).
//
// A zero difficulty (the default) disables the check, leaving the node's prior
// behaviour untouched. If d > 0 and puzzle is nil, DefaultArgon2id is used. Call
// before Register. The check only applies when a ledger is set (no ledger = an
// unauthenticated blob store with no owner identity to gate).
func (srv *Server) SetPoW(puzzle cap.Puzzle, d cap.Difficulty) {
	if d > 0 && puzzle == nil {
		puzzle = cap.DefaultArgon2id()
	}
	srv.powPuzzle, srv.powMin = puzzle, d
}

// enforcePoW reports whether owner satisfies the node's proof-of-work admission
// policy, returning ErrUnauthorized if not. A zero minimum difficulty accepts
// any owner (the check is disabled).
func (srv *Server) enforcePoW(owner []byte) error {
	if srv.powMin == 0 {
		return nil
	}
	if !cap.MeetsPoW(srv.powPuzzle, owner, srv.powMin) {
		return ErrUnauthorized
	}
	return nil
}

// Register installs the Server's stream handlers on h. After this the host will
// serve /revika/shard and /revika/probe to any peer that dials them.
func (srv *Server) Register(h host.Host) {
	h.SetStreamHandler(ShardProtocol, srv.handleShard)
	h.SetStreamHandler(ProbeProtocol, srv.handleProbe)
	h.SetStreamHandler(BalanceProtocol, srv.handleLoad)
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
	start := time.Now()
	data, err := readBlob(s, MaxShardSize)
	if err != nil {
		srv.log.Debug("shard put: read blob", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	// Three length-prefixed blobs always follow the data (empty when unused), so
	// the frame is uniform: the auth token, then the stripe descriptor and repair
	// grant that let this node take part in repairing the shard later. They are
	// only interpreted when a ledger is configured.
	token, err := readBlob(s, authTokenSize)
	if err != nil {
		srv.log.Debug("shard put: read token", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	stripeBytes, err := readBlob(s, maxStripeBlob)
	if err != nil {
		srv.log.Debug("shard put: read stripe", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	grant, err := readBlob(s, stripe.GrantSize)
	if err != nil {
		srv.log.Debug("shard put: read grant", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	id := store.HashOf(data)

	// Parse and validate any accompanying stripe descriptor + grant once. desc is
	// only usable (recordable, or usable as authorization) when the grant validly
	// signs it and it actually names this shard. A bad descriptor never blocks a
	// token-authorized PUT — it is simply not recorded.
	now := time.Now()
	var (
		desc       stripe.Descriptor
		grantOwner []byte
		stripeOK   bool
	)
	if len(stripeBytes) > 0 && len(grant) > 0 {
		if d, derr := stripe.UnmarshalDescriptor(stripeBytes); derr == nil {
			if o, gerr := stripe.VerifyGrant(grant, d, now); gerr == nil && d.Contains(id) {
				desc, grantOwner, stripeOK = d, o, true
			}
		}
	}

	var owner []byte
	if srv.ledger != nil {
		// Authorization: a signed owner token takes precedence; failing that, a
		// valid repair grant naming this shard authorizes a regenerated copy
		// under the granting User's ownership.
		switch {
		case len(token) > 0:
			owner, err = verifyToken(token, opPut, id, s.Conn().LocalPeer(), now)
			if err != nil {
				srv.log.Debug("shard put: unauthorized", "event", "shard.put.rejected", "reason", "bad_token", "peer", peer, "id", id, "err", err)
				srv.replyErr(s, err)
				return
			}
			// Proof-of-work admission: a fresh, owner-initiated write is only
			// accepted from a self-certifying identity meeting the node's
			// difficulty. This gates the abuse vector (an owner injecting new
			// load), so it applies to token writes but NOT to the grant branch
			// below: repair regenerates already-admitted, content-addressed data
			// under an owner vouched for at store time, and repair is mandatory —
			// gating it would strand data whose owner predates the current bar.
			// DELETE is likewise ungated (owner-scoped, drops only the caller's
			// own claim).
			if err := srv.enforcePoW(owner); err != nil {
				srv.log.Debug("shard put: owner fails proof-of-work", "event", "shard.put.rejected", "reason", "proof_of_work", "peer", peer, "id", id, "min_bits", srv.powMin)
				srv.replyErr(s, err)
				return
			}
		case stripeOK:
			owner = grantOwner
		default:
			srv.log.Debug("shard put: unauthorized (no token or valid grant)", "event", "shard.put.rejected", "reason", "no_credential", "peer", peer, "id", id)
			srv.replyErr(s, ErrUnauthorized)
			return
		}
	}

	// Store the bytes first, then record ownership. A crash in between leaves an
	// orphan blob (reclaimed by GC/reconcile), never lost owner data.
	if _, err := srv.store.Put(ctx, data); err != nil {
		srv.log.Warn("shard put: store", "peer", peer, "err", err)
		srv.replyErr(s, err)
		return
	}
	if srv.ledger != nil {
		added, err := srv.ledger.AddOwner(id, owner, int64(len(data)), now)
		if err != nil {
			// Quota exceeded (or a ledger error): the blob just written is now an
			// unowned orphan, left for GC to reclaim. Do not announce it.
			srv.log.Debug("shard put: ledger", "event", "shard.put.rejected", "reason", "quota", "peer", peer, "id", id, "err", err)
			srv.replyErr(s, err)
			return
		}
		if added {
			// Record the erasure context so this node can help repair the stripe.
			// The FK ties the row to the shard, so it cascades away on GC/delete.
			if stripeOK {
				if err := srv.ledger.PutStripe(id, desc.K, desc.M, desc.Shards, grant); err != nil {
					srv.log.Warn("shard put: record stripe", "peer", peer, "id", id, "err", err)
				}
			}
			srv.announce(id)
		}
	} else {
		srv.announce(id)
	}
	// A shard has been accepted and stored: this is the node fulfilling its one
	// job (taking in an encrypted, erasure-coded blob), so surface it at Info.
	srv.log.Info("shard received",
		"event", "shard.put", "peer", peer, "id", id, "bytes", len(data), "stripe", stripeOK,
		"dur", time.Since(start).Round(time.Millisecond))
	// OK + the content address the caller can verify against its own hash.
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeID(s, id)
}

// announce advertises a freshly stored shard as a DHT provider record, if an
// announcer is configured. It runs in the background with its own timeout so it
// never blocks the Put response and survives the request stream closing (a
// Provide fan-out can outlast the client's request).
func (srv *Server) announce(id store.ShardID) {
	if srv.announcer == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), provideTimeout)
		defer cancel()
		if err := srv.announcer.Announce(ctx, id); err != nil {
			srv.log.Debug("announce failed", "id", id, "err", err)
		} else {
			srv.log.Debug("announced shard", "id", id)
		}
	}()
}

func (srv *Server) handleGet(ctx context.Context, s network.Stream, peer any) {
	start := time.Now()
	id, err := readID(s)
	if err != nil {
		srv.log.Debug("shard get: read id", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	data, err := srv.store.Get(ctx, id)
	if err != nil {
		srv.log.Debug("shard get: miss", "event", "shard.get.miss", "peer", peer, "id", id, "err", err)
		srv.replyErr(s, err)
		return
	}
	if err := writeByte(s, byte(statusOK)); err != nil {
		return
	}
	_ = writeBlob(s, data)
	// A shard has been served out to a peer: the node's other core job, so log
	// it at Info alongside reception.
	srv.log.Info("shard served",
		"event", "shard.get", "peer", peer, "id", id, "bytes", len(data),
		"dur", time.Since(start).Round(time.Millisecond))
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
		srv.log.Debug("shard has: store", "event", "shard.has", "peer", peer, "id", id, "err", err)
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
	srv.log.Debug("shard has", "event", "shard.has", "peer", peer, "id", id, "present", ok)
}

func (srv *Server) handleDelete(ctx context.Context, s network.Stream, peer any) {
	id, err := readID(s)
	if err != nil {
		srv.log.Debug("shard delete: read id", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}
	token, err := readBlob(s, authTokenSize)
	if err != nil {
		srv.log.Debug("shard delete: read token", "peer", peer, "err", err)
		_ = s.Reset()
		return
	}

	// Without a ledger the node is an unauthenticated blob store: delete
	// unconditionally (legacy/test behaviour).
	if srv.ledger == nil {
		if err := srv.store.Delete(ctx, id); err != nil {
			srv.replyErr(s, err)
			return
		}
		srv.log.Info("shard deleted", "event", "shard.delete", "peer", peer, "id", id, "removed", true)
		_ = writeByte(s, byte(statusOK))
		return
	}

	owner, err := verifyToken(token, opDelete, id, s.Conn().LocalPeer(), time.Now())
	if err != nil {
		srv.log.Debug("shard delete: unauthorized", "peer", peer, "id", id, "err", err)
		srv.replyErr(s, err)
		return
	}
	// Drop only this owner's claim. ErrUnauthorized here means the caller never
	// owned the shard — so it cannot delete another User's data.
	remaining, err := srv.ledger.RemoveOwner(id, owner)
	if err != nil {
		srv.log.Debug("shard delete: remove owner", "peer", peer, "id", id, "err", err)
		srv.replyErr(s, err)
		return
	}
	// Physically remove the blob only when the last owner has left. Ledger
	// remove precedes blob delete; a crash in between leaves an orphan blob GC
	// reclaims, and a racing re-PUT self-heals.
	if remaining == 0 {
		if err := srv.store.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			srv.replyErr(s, err)
			return
		}
		if err := srv.ledger.DropRecord(id); err != nil {
			srv.replyErr(s, err)
			return
		}
	}
	// A claim was dropped: log it at Info, noting whether that emptied the last
	// owner (removed=true) and the blob was physically deleted, or the shard
	// lives on for its other owners.
	srv.log.Info("shard deleted", "event", "shard.delete", "peer", peer, "id", id, "removed", remaining == 0, "owners_left", remaining)
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
		// The node cannot answer the challenge for a shard it does not hold — the
		// RX-side signal of a failed possession proof (a mover's proof-gated release
		// keys off exactly this, Architecture §3.4). Structured so it is filterable
		// alongside the successful `probe` event.
		srv.log.Debug("probe: miss", "event", "probe.miss", "peer", peer, "id", id, "err", err)
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
	// Probes are a frequent repair heartbeat, so this stays at Debug — it proves
	// the node answered a possession challenge for a shard it holds.
	srv.log.Debug("probe answered", "event", "probe", "peer", peer, "id", id)
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
