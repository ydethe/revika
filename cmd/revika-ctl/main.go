// Command revika-ctl is the User-side client: it stores files on a revika Node,
// retrieves them, and shares them end-to-end encrypted with other users. All
// the intelligence lives here on the client — chunking, encryption, erasure
// coding, and capability wrapping — so the node it talks to only ever sees
// opaque, content-addressed shards.
//
// Usage:
//
//	revika-ctl keygen [-key <prefix>]
//	revika-ctl put     -node <multiaddr> [-manifest <path>] [-r] <file>
//	revika-ctl get     -node <multiaddr> (-manifest <path> | -cap <path> -key <privkey>) [-o <out>]
//	revika-ctl sync    -node <multiaddr> (-manifest <path> | -cap <path> -key <privkey>) -o <dir>
//	revika-ctl hydrate -node <multiaddr> [-C <syncdir>] <path>...
//	revika-ctl share   -manifest <path> -to <recipient-pubkey|@file> [-path <subpath>] [-o <path>]
//
// A <multiaddr> is a node's full dial address including its peer ID, e.g.
// /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW…, as printed by revika-node on startup.
package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/fsmeta"
	"revika/internal/net"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// ctlLog is the client's logger. It reports discovery activity (each new storage
// node found via the DHT or mDNS) to stderr so the User can see the network
// forming under put/get/nodes.
var ctlLog = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "keygen":
		err = cmdKeygen(args)
	case "put":
		err = cmdPut(args)
	case "get":
		err = cmdGet(args)
	case "sync":
		err = cmdSync(args)
	case "hydrate":
		err = cmdHydrate(args)
	case "delete", "rm":
		err = cmdDelete(args)
	case "share":
		err = cmdShare(args)
	case "nodes":
		err = cmdNodes(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "revika-ctl: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "revika-ctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `revika-ctl — revika User client

Commands:
  keygen [-key <prefix>] [-pow-puzzle argon2id|sha256] [-pow-difficulty <bits>]
        Generate the User identity: an ML-KEM-768 (FIPS 203) keypair for receiving shared files
        (<prefix>.key/.pub) and an Ed25519 signing keypair that is your storage
        owner identity (<prefix>.sign.key/.sign.pub). Default prefix:
        .revika/keys/user
        The signing key is self-certifying: it is ground until its public key
        satisfies a proof-of-work target (-pow-difficulty leading zero bits under
        -pow-puzzle), so it costs seconds-to-minutes to mint but one hash to
        verify — a banned owner cannot re-mint an identity for free. Default
        argon2id (memory-hard) at 12 bits; -pow-difficulty 0 disables it.

  put (-node <ma> | -bootstrap <ma>... | -mdns) [-manifest <path>] [-signkey <path>] [-r] <file>
        Chunk, encrypt, erasure-code and store <file>. With -node, store on that
        single node; with -bootstrap/-mdns, join the DHT and spread the shards
        across discovered storage nodes. Writes the file's manifest (its
        read-capability) to <path> (default <file>.rvk.json). Signs the store
        with your signing key so you (and only you) can later delete it.
        With -r, <file> is a directory: it is stored as a Merkle DAG of
        cap-addressed encrypted blobs (each file a manifest blob, each folder a
        directory blob), and -manifest receives the tree's root cap.

  get (-node <ma> | -bootstrap <ma>... | -mdns) (-manifest <path> | -cap <path> -key <privkey>) [-o <out>] [-r]
        Reconstruct a file or a directory tree. With -node, fetch from that node;
        with -bootstrap/-mdns, discover each shard's providers via the DHT. Read
        your own data with -manifest, or shared data by unwrapping a -cap with
        your -key. Whether the capability is a single file or a directory is
        auto-detected from the capability itself (its Kind), so it also restores a
        single file or subtree carved out of a tree with 'share -path'. A single
        file writes to its original name (recorded in the manifest) unless -o is
        given, falling back to stdout when it carries none; a directory is
        restored into the -o directory (required). -r is an optional hint.

  sync (-node <ma> | -bootstrap <ma>... | -mdns) (-manifest <path> | -cap <path> -key <privkey>) -o <dir>
        Materialize the directory tree's namespace into -o WITHOUT downloading
        file content: it fetches only the directory blobs and recreates the
        folders, symlinks, and empty file placeholders, then writes a
        .revika-sync.json index mapping each placeholder to its file cap. Cheap
        to browse a whole tree; pull bytes later with 'hydrate'.

  hydrate (-node <ma> | -bootstrap <ma>... | -mdns) [-C <syncdir>] <path>...
        Fill previously-synced placeholders with real content. Each <path> is a
        placeholder file or a directory (its whole subtree) inside a synced tree;
        the sync root is found by ascending to the nearest .revika-sync.json, or
        set it with -C. With -C and no <path>, the whole tree is hydrated. Only
        the wanted files' shards are fetched.

  delete (-node <ma> | -bootstrap <ma>... | -mdns) -manifest <path> [-signkey <path>]
        Drop your ownership claim on every shard of the file. A node frees a
        shard's bytes only once its last owner deletes, so this never affects
        another User's copy of shared data. (Alias: rm)

  share -manifest <path> -to <recipient-pubkey|@file> [-path <subpath>] [-o <path>]
        [-node <ma> | -bootstrap <ma>... | -mdns]
        Wrap a read-capability to a recipient's public key so only they can open
        it. The -manifest may be a single file's manifest (from 'put') or a
        directory root cap (from 'put -r'); wrapping either is local, no node
        contact. With -path, share only the file or subdirectory at that
        slash-separated path within a tree — this resolves the tree, so it needs a
        -node/-bootstrap/-mdns backend. Sharing a directory cap grants read access
        to that whole subtree and nothing outside it. Writes <path>.cap by default.

  nodes (-bootstrap <ma>... | -mdns)
        List the storage nodes the client can discover on the DHT — the nodes it
        is aware of and could place shards on. Reports each node's peer ID,
        reachability, and advertised addresses. No file contact.

A <multiaddr> includes the node's peer ID, e.g.
  /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...
as printed by revika-node on startup. A -bootstrap peer is any running node; the
client joins the revika DHT through it and needs no central server.
`)
}

// --- shared helpers -------------------------------------------------------

// multiFlag collects a repeatable string flag (e.g. -bootstrap a -bootstrap b).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// dialTimeout bounds establishing the client→node connection.
const dialTimeout = 30 * time.Second

// discoveryTimeout bounds a DHT discovery step (finding storage nodes or a
// shard's providers) before we give up.
const discoveryTimeout = 30 * time.Second

// dialHost builds an ephemeral client host (no persistent identity, no mDNS)
// and connects it to the node at nodeAddr, returning the host, the node's peer
// ID, and a closer.
func dialHost(ctx context.Context, nodeAddr string) (host.Host, peer.ID, func(), error) {
	if nodeAddr == "" {
		return nil, "", nil, fmt.Errorf("missing -node <multiaddr>")
	}
	info, err := peer.AddrInfoFromString(nodeAddr)
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid -node address %q: %w", nodeAddr, err)
	}
	h, err := net.NewHost(net.HostConfig{}) // ephemeral identity, random port, mDNS off
	if err != nil {
		return nil, "", nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := net.Connect(cctx, h, *info); err != nil {
		h.Close()
		return nil, "", nil, err
	}
	return h, info.ID, func() { h.Close() }, nil
}

// dial returns an unauthenticated NetStore over a single node — for reads, or a
// node that runs no ledger.
func dial(ctx context.Context, nodeAddr string) (*net.NetStore, func(), error) {
	h, id, closer, err := dialHost(ctx, nodeAddr)
	if err != nil {
		return nil, nil, err
	}
	return net.NewNetStore(h, id), closer, nil
}

// dialSigned returns a NetStore over a single node whose PUT/DELETE carry an
// authorization token signed by signer — for writes to a ledger-backed node.
func dialSigned(ctx context.Context, nodeAddr string, signer cap.SignKey) (*net.NetStore, func(), error) {
	h, id, closer, err := dialHost(ctx, nodeAddr)
	if err != nil {
		return nil, nil, err
	}
	return net.NewNetStoreSigned(h, id, signer), closer, nil
}

// joinDHT builds an ephemeral client-mode DHT host and joins the network via the
// given bootstrap peers (and/or mDNS on the LAN). It returns the host, the
// Discovery, and a closer that tears both down. At least one of bootstrap/mdns
// must be provided — a client with no way in cannot reach the DHT.
func joinDHT(ctx context.Context, bootstrap []string, mdns bool) (host.Host, *net.Discovery, func(), error) {
	if len(bootstrap) == 0 && !mdns {
		return nil, nil, nil, fmt.Errorf("DHT mode needs -bootstrap <multiaddr> (or -mdns on a LAN)")
	}
	h, err := net.NewHost(net.HostConfig{EnableMDNS: mdns, Log: ctlLog})
	if err != nil {
		return nil, nil, nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	disc, err := net.NewDiscovery(dctx, h, net.DiscoveryConfig{Mode: net.DHTModeClient, Bootstrap: bootstrap, Log: ctlLog})
	if err != nil {
		h.Close()
		return nil, nil, nil, err
	}
	closer := func() { disc.Close(); h.Close() }
	// The routing table fills asynchronously after bootstrap; wait for it before
	// querying, or the first lookup races an empty table and finds nothing.
	rctx, rcancel := context.WithTimeout(ctx, discoveryTimeout)
	defer rcancel()
	if err := disc.WaitReady(rctx); err != nil {
		closer()
		return nil, nil, nil, err
	}
	return h, disc, closer, nil
}

// dialDHT returns a read store that retrieves shards by discovering their
// providers on the DHT — no explicit node needed. Used by `get`.
func dialDHT(ctx context.Context, bootstrap []string, mdns bool) (store.Store, func(), error) {
	h, disc, closer, err := joinDHT(ctx, bootstrap, mdns)
	if err != nil {
		return nil, nil, err
	}
	return net.NewDHTStore(h, disc), closer, nil
}

// dialPlacement joins the DHT, discovers storage nodes, and returns a
// PlacementStore that spreads shards across them, signing writes with signer.
// Used by `put` and `delete`.
func dialPlacement(ctx context.Context, bootstrap []string, mdns bool, signer cap.SignKey) (*net.PlacementStore, func(), error) {
	h, disc, closer, err := joinDHT(ctx, bootstrap, mdns)
	if err != nil {
		return nil, nil, err
	}
	fctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	nodes, err := discoverNodes(fctx, h, disc)
	if err != nil {
		closer()
		return nil, nil, err
	}
	ps, err := net.NewPlacementStore(h, disc, nodes, signer)
	if err != nil {
		closer()
		return nil, nil, err
	}
	return ps, closer, nil
}

// discoverNodes finds storage nodes advertised on the DHT and connects to them,
// returning the peer IDs of those we could reach. DHT discovery is eventually
// consistent — advertise records and routing tables converge asynchronously — so
// it polls, accumulating reachable nodes across rounds, and returns once a round
// turns up nothing new (the reachable set has stabilised) or the timeout hits.
func discoverNodes(ctx context.Context, h host.Host, disc *net.Discovery) ([]peer.ID, error) {
	seen := map[peer.ID]bool{}
	var ids []peer.ID
	prev := -1
	deadline := time.Now().Add(discoveryTimeout)
	for time.Now().Before(deadline) {
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		infos, err := disc.FindNodes(fctx, 0)
		cancel()
		if err == nil {
			for _, pi := range infos {
				if seen[pi.ID] {
					continue
				}
				cctx, c := context.WithTimeout(ctx, dialTimeout)
				connErr := net.Connect(cctx, h, pi)
				c()
				if connErr == nil {
					seen[pi.ID] = true
					ids = append(ids, pi.ID)
				}
			}
		}
		// Once we have at least one node and a round added nothing new, the
		// reachable set has settled — stop waiting for stragglers.
		if len(ids) > 0 && len(ids) == prev {
			return ids, nil
		}
		prev = len(ids)
		time.Sleep(1500 * time.Millisecond)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no storage nodes discovered via the DHT (is a node running, advertising, and reachable?)")
	}
	return ids, nil
}

// nodeInfo pairs a discovered storage node with whether we could reach it.
type nodeInfo struct {
	Info      peer.AddrInfo
	Reachable bool
}

// discoverNodeInfos polls the DHT for advertised storage nodes so `nodes` can
// report what the client is aware of. Like discoverNodes it polls (DHT
// discovery is eventually consistent) and attempts to connect to each so it can
// report reachability, but it keeps every node it hears about — reachable or
// not — along with the addresses it advertised. It returns once a round turns up
// no new node and no newly-reachable node (the view has settled) or the timeout
// hits; unlike discoverNodes it never errors on an empty result — "no nodes" is
// a valid thing to report.
func discoverNodeInfos(ctx context.Context, h host.Host, disc *net.Discovery) []nodeInfo {
	idx := map[peer.ID]int{} // peer.ID -> position in out
	var out []nodeInfo
	prevSeen, prevReachable := -1, -1
	deadline := time.Now().Add(discoveryTimeout)
	for time.Now().Before(deadline) {
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		infos, err := disc.FindNodes(fctx, 0)
		cancel()
		if err == nil {
			for _, pi := range infos {
				i, ok := idx[pi.ID]
				if !ok {
					i = len(out)
					idx[pi.ID] = i
					out = append(out, nodeInfo{Info: pi})
				} else if len(out[i].Info.Addrs) == 0 {
					out[i].Info.Addrs = pi.Addrs // fill in addrs a later round supplied
				}
				if !out[i].Reachable {
					cctx, c := context.WithTimeout(ctx, dialTimeout)
					connErr := net.Connect(cctx, h, pi)
					c()
					out[i].Reachable = connErr == nil
				}
			}
		}
		reachable := 0
		for _, n := range out {
			if n.Reachable {
				reachable++
			}
		}
		// Settle once a round added no node and flipped none to reachable.
		if len(out) == prevSeen && reachable == prevReachable {
			break
		}
		prevSeen, prevReachable = len(out), reachable
		time.Sleep(1500 * time.Millisecond)
	}
	return out
}

// runStore stores the file at path into s and returns its manifest. Split out
// so tests can drive it with an in-process store.
func runStore(ctx context.Context, s store.Store, cfg pipeline.Config, path string) (pipeline.FileManifest, error) {
	// Lstat (not Stat) so a symlink is captured as a link rather than followed:
	// its "content" is its target path, stored so `get` can recreate the link.
	fi, err := os.Lstat(path)
	if err != nil {
		return pipeline.FileManifest{}, err
	}

	var m pipeline.FileManifest
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return pipeline.FileManifest{}, err
		}
		m, err = pipeline.StoreFile(ctx, s, cfg, strings.NewReader(target))
		if err != nil {
			return pipeline.FileManifest{}, err
		}
	} else {
		f, err := os.Open(path)
		if err != nil {
			return pipeline.FileManifest{}, err
		}
		defer f.Close()
		m, err = pipeline.StoreFile(ctx, s, cfg, f)
		if err != nil {
			return pipeline.FileManifest{}, err
		}
	}

	// Record the original file name and filesystem attributes so `get` (and a
	// native cloud-provider mount, §3.8) can restore the file faithfully, then
	// derive the content/metadata version tokens from the finished manifest.
	m.Name = filepath.Base(path)
	m.Meta = fsmeta.Capture(path, fi)
	pipeline.DeriveVersions(&m)
	return m, nil
}

// runLoad reconstructs the file described by m from s into w.
func runLoad(ctx context.Context, s store.Store, m pipeline.FileManifest, w io.Writer) error {
	return pipeline.LoadFile(ctx, s, m, w)
}

// resolveRecipient reads a recipient public key from a literal base64 string or,
// if prefixed with '@', from a file (as written by keygen's .pub).
func resolveRecipient(to string) (cap.PublicKey, error) {
	if to == "" {
		return cap.PublicKey{}, fmt.Errorf("missing -to <recipient-pubkey|@file>")
	}
	s := to
	if strings.HasPrefix(to, "@") {
		raw, err := os.ReadFile(to[1:])
		if err != nil {
			return cap.PublicKey{}, fmt.Errorf("read recipient key file: %w", err)
		}
		s = strings.TrimSpace(string(raw))
	}
	return cap.ParsePublicKey(s)
}
