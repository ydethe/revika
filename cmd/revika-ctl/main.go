// Command revika-ctl is the User-side client: it stores files in a revika
// namespace, retrieves them, and shares subtrees end-to-end encrypted with other
// users. All the intelligence lives here on the client — chunking, encryption,
// erasure coding, and capability wrapping — so the node it talks to only ever
// sees opaque, content-addressed shards.
//
// The namespace is one mutable root directory per User, addressed by rvk: paths
// into whichever root file is in effect (-root, default .revika/root.json). Your
// own root is mutable; a root someone shared with you is read-only.
//
// A workspace ties this together: `connect` writes a folder (default .revika)
// holding config.json — the bootstrap peers, erasure k/m, and node proof-of-work
// policy — alongside where root.json and the User's keys live. Every namespace
// command selects it with -root <folder> and then needs no per-command backend
// flags; the identity is minted on the first write, after a confirmation prompt.
//
// Usage:
//
//	revika-ctl connect (-bootstrap <ma>… | <ma>…) [-root <dir>] [-label <s>] [-k 4] [-m 2] [-pow-…]
//	revika-ctl keygen [-key <prefix>]
//	revika-ctl cp    [-root <ws>] [backend] <local> rvk:<path>            # store
//	revika-ctl cp    [-root <ws>] [backend] rvk:<path> <local>           # retrieve
//	revika-ctl ls    [-root <ws>] [backend] [-l] [-R] [rvk:<path>]       # browse
//	revika-ctl rm     [-root <ws>] [backend] rvk:<path>                  # delete
//	revika-ctl revoke [-root <ws>] [backend] rvk:<path>                  # rotate caps
//	revika-ctl share [-root <ws>] [backend] rvk:<path> -to <pubkey-file> [-o <file>]
//	revika-ctl node  [-root <ws>]                                        # list nodes
//
// [backend] is -node <ma>; it overrides the workspace config's bootstrap peers
// when given, which otherwise supply the DHT entry point. -root accepts a
// workspace folder or a bare
// root file (a plaintext own root, or a sealed shared root opened with -key). A
// <multiaddr> is a node's full dial address including its peer ID, e.g.
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
// node found via the DHT) to stderr so the User can see the network forming under
// cp/ls/node.
var ctlLog = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "connect":
		err = cmdConnect(args)
	case "keygen":
		err = cmdKeygen(args)
	case "cp":
		err = cmdCp(args)
	case "ls":
		err = cmdLs(args)
	case "rm":
		err = cmdRm(args)
	case "revoke":
		err = cmdRevoke(args)
	case "share":
		err = cmdShare(args)
	case "node":
		err = cmdNode(args)
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

Your files live in a namespace: one mutable root directory addressed by rvk: paths
(e.g. rvk:docs/report.pdf). A workspace folder (default .revika, made by connect)
groups the connection profile (config.json), the namespace anchor (root.json), and
your keys; every command selects it with -root <folder>. Your own root is mutable;
a root someone shared with you (opened with -root <file> -key <privkey>) is
read-only.

Every rvk: command reaches nodes over the DHT through the bootstrap peers saved in
the workspace's config.json (set by connect), so you rarely pass a backend. Override
it per command with -node <ma> to pin a single node.

Commands:
  connect (-bootstrap <ma>… | <ma>…) [-root <dir>] [-label <s>] [-k 4] [-m 2]
          [-pow-puzzle argon2id|sha256] [-pow-difficulty <bits>] [-force]
        Create a workspace folder (default .revika) with a config.json recording
        the bootstrap peer(s), erasure parameters (k data + m parity, default
        4+2), the node's proof-of-work admission policy, and an optional label.
        root.json and your keys live in the same folder. Writes no keys itself —
        your identity is minted on the first write (cp/rm/share), after a prompt.

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

  cp [-root <ws|file>] [backend] [-key <privkey>] [-signkey <path>] <src> <dst>
        Copy between the local filesystem and the namespace; exactly one of <src>/<dst>
        carries the rvk: prefix. In a workspace the backend defaults to config.json's
        bootstrap peers, and a first store mints your identity after a prompt.
          cp report.pdf rvk:docs/      store report.pdf as docs/report.pdf
          cp report.pdf rvk:docs/r.pdf store under a chosen name
          cp rvk:docs/report.pdf .     retrieve into the current directory
          cp rvk:docs ./out            retrieve a whole subtree into ./out
        Storing chunks, encrypts, erasure-codes and grafts the file (or directory
        subtree) into your -root, then advances the root's sequence — signed with your
        signing key. Retrieving resolves the rvk: path and reconstructs it. A trailing
        slash (or an existing rvk: directory) means "into that directory".

  ls [-root <ws|file>] [backend] [-key <privkey>] [-owner <pubkey-file>] [-l] [-R] [rvk:<path>]
        List a directory in the namespace. Reads directory blobs only — no file
        content is fetched. Plain output is one name per line (directories end in /);
        -l adds kind, size and mtime; -R recurses. 'ls' or 'ls rvk:' lists the root.
        -owner <file> reads a signing pubkey from that file and instead resolves that
        identity's published root from the DHT, printing its (verify-only) summary —
        liveness and revocation detection; decrypting still needs the read key from a
        sealed share.

  rm [-root <ws|file>] [backend] [-signkey <path>] rvk:<path>
        Remove <path> from your -root (a file or a whole subtree) and drop your
        ownership claim on its shards. A node frees a shard's bytes only once its last
        owner leaves, so this never affects another User's shared copy. Owned root only.

  revoke [-root <ws|file>] [backend] [-signkey <path>] rvk:<path>
        Rotate the read-capabilities of a subtree (rvk: alone = the whole namespace):
        re-encrypt every blob under it down to the data chunks with fresh keys, graft
        the result into a new root, advance and republish the pointer, and reclaim the
        orphaned old shards. A previously-shared cap can no longer read the current
        data. Already-downloaded copies cannot be recalled. Owned root only.

  share [-root <ws|file>] [backend] [-key <privkey>] [-signkey <path>] rvk:<path>
        -to <recipient-pubkey-file> [-o <file>]
        Wrap a read-capability to the subtree at rvk:<path> for a recipient: it builds
        a RootPointer anchored there, signed by you, and SEALS it to the recipient's
        public key, read from the -to file (only they can open it). Writes a shared
        root file (default
        <name>.root.json). The recipient reads it with:
          revika-ctl ls -root <file> -key <their-privkey>
          revika-ctl cp -root <file> -key <their-privkey> rvk:… <dst>

  node [-root <ws>]
        List the storage nodes the client can discover on the DHT — the nodes it
        is aware of and could place shards on. Joins through the workspace's saved
        bootstrap peers (-root). Reports each node's peer ID, reachability, and
        advertised addresses. No file contact.

A <multiaddr> includes the node's peer ID, e.g.
  /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...
as printed by revika-node on startup. A bootstrap peer is any running node; the
client joins the revika DHT through the one(s) saved in the workspace by connect,
and needs no central server.

Note: a write to your own root also publishes the signed pointer to the DHT
(key-stripped, so nodes learn location + integrity but never a decryption key), so
others can resolve it with 'ls -owner <your-pubkey-file>'. Sharing a readable subtree
across machines still travels as the sealed file above (it carries the read key).
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

// dialHost builds an ephemeral client host (no persistent identity) and connects
// it to the node at nodeAddr, returning the host, the node's peer
// ID, and a closer.
func dialHost(ctx context.Context, nodeAddr string) (host.Host, peer.ID, func(), error) {
	if nodeAddr == "" {
		return nil, "", nil, fmt.Errorf("missing -node <multiaddr>")
	}
	info, err := peer.AddrInfoFromString(nodeAddr)
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid -node address %q: %w", nodeAddr, err)
	}
	h, err := net.NewHost(net.HostConfig{}) // ephemeral identity, random port
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
// given bootstrap peers. It returns the host, the Discovery, and a closer that
// tears both down. At least one bootstrap peer must be provided — a client with
// no way in cannot reach the DHT.
func joinDHT(ctx context.Context, bootstrap []string) (host.Host, *net.Discovery, func(), error) {
	if len(bootstrap) == 0 {
		return nil, nil, nil, fmt.Errorf("DHT mode needs a workspace with saved bootstrap peers (select it with -root, set by connect)")
	}
	h, err := net.NewHost(net.HostConfig{Log: ctlLog})
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
// providers on the DHT — no explicit node needed. Used by `cp` (retrieve)/`ls`.
func dialDHT(ctx context.Context, bootstrap []string) (store.Store, func(), error) {
	h, disc, closer, err := joinDHT(ctx, bootstrap)
	if err != nil {
		return nil, nil, err
	}
	return net.NewDHTStore(h, disc), closer, nil
}

// dialPlacement joins the DHT, discovers storage nodes, and returns a
// PlacementStore that spreads shards across them, signing writes with signer.
// Used by `cp` (store) and `rm`.
func dialPlacement(ctx context.Context, bootstrap []string, signer cap.SignKey) (*net.PlacementStore, func(), error) {
	h, disc, closer, err := joinDHT(ctx, bootstrap)
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

// resolveRecipient reads a recipient public key from the file at path (as written
// by keygen's .pub). The key is never accepted as a literal on the command line —
// only a file path is — so a pubkey is never exposed in shell history or argv.
func resolveRecipient(path string) (cap.PublicKey, error) {
	if path == "" {
		return cap.PublicKey{}, fmt.Errorf("missing -to <recipient-pubkey-file>")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cap.PublicKey{}, fmt.Errorf("read recipient key file: %w", err)
	}
	return cap.ParsePublicKey(strings.TrimSpace(string(raw)))
}
