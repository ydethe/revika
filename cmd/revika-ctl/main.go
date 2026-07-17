// Command revika-ctl is the User-side client: it stores files on a revika Node,
// retrieves them, and shares them end-to-end encrypted with other users. All
// the intelligence lives here on the client — chunking, encryption, erasure
// coding, and capability wrapping — so the node it talks to only ever sees
// opaque, content-addressed shards.
//
// Usage:
//
//	revika-ctl keygen [-key <prefix>]
//	revika-ctl put    -node <multiaddr> [-manifest <path>] <file>
//	revika-ctl get    -node <multiaddr> (-manifest <path> | -cap <path> -key <privkey>) [-o <out>]
//	revika-ctl share  -manifest <path> -to <recipient-pubkey|@file> [-o <path>]
//
// A <multiaddr> is a node's full dial address including its peer ID, e.g.
// /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW…, as printed by revika-node on startup.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/net"
	"revika/internal/pipeline"
	"revika/internal/store"
)

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
	case "share":
		err = cmdShare(args)
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
  keygen [-key <prefix>]
        Generate an X25519 identity for receiving shared files. Writes
        <prefix>.key (private) and <prefix>.pub (public); prints the public key.
        Default prefix: .revika/keys/user

  put -node <multiaddr> [-manifest <path>] <file>
        Chunk, encrypt, erasure-code and store <file> on the node. Writes the
        file's manifest (its read-capability) to <path> (default <file>.rvk.json).

  get -node <multiaddr> (-manifest <path> | -cap <path> -key <privkey>) [-o <out>]
        Reconstruct a file from the node. Read your own file with -manifest, or a
        shared file by unwrapping a -cap with your private -key. Default out: stdout.

  share -manifest <path> -to <recipient-pubkey|@file> [-o <path>]
        Wrap a manifest (read-capability) to a recipient's public key so only they
        can open it. Writes <path>.cap by default. No node contact.

A <multiaddr> includes the node's peer ID, e.g.
  /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...
as printed by revika-node on startup.
`)
}

// --- shared helpers -------------------------------------------------------

// dialTimeout bounds establishing the client→node connection.
const dialTimeout = 30 * time.Second

// dial builds an ephemeral client host (no persistent identity, no mDNS),
// connects it to the node at nodeAddr, and returns a NetStore over that node
// plus a closer for the host.
func dial(ctx context.Context, nodeAddr string) (*net.NetStore, func(), error) {
	if nodeAddr == "" {
		return nil, nil, fmt.Errorf("missing -node <multiaddr>")
	}
	info, err := peer.AddrInfoFromString(nodeAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid -node address %q: %w", nodeAddr, err)
	}
	h, err := net.NewHost(net.HostConfig{}) // ephemeral identity, random port, mDNS off
	if err != nil {
		return nil, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := net.Connect(cctx, h, *info); err != nil {
		h.Close()
		return nil, nil, err
	}
	closer := func() { h.Close() }
	return net.NewNetStore(h, info.ID), closer, nil
}

// runStore stores the file at path into s and returns its manifest. Split out
// so tests can drive it with an in-process store.
func runStore(ctx context.Context, s store.Store, cfg pipeline.Config, path string) (pipeline.FileManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return pipeline.FileManifest{}, err
	}
	defer f.Close()
	return pipeline.StoreFile(ctx, s, cfg, f)
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
