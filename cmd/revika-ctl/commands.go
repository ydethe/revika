package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"revika/internal/cap"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// cmdKeygen generates and persists a recipient identity.
func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	prefix := fs.String("key", filepath.Join(".revika", "keys", "user"), "path prefix for the identity (writes <prefix>.key and <prefix>.pub)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	privPath := *prefix + ".key"
	pubPath := *prefix + ".pub"
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing private key %s", privPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(privPath, []byte(priv.String()+"\n"), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pub.String()+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Printf("Identity written:\n  private: %s (keep secret)\n  public:  %s\n\n", privPath, pubPath)
	fmt.Println("Public key (share this so others can send you files):")
	fmt.Println(pub.String())
	return nil
}

// cmdPut stores a file and writes its manifest. It targets either a single node
// (-node) or, via the DHT, a set of discovered nodes across which the shards are
// spread (-bootstrap / -mdns).
func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	node := fs.String("node", "", "store on this single node multiaddr (with /p2p/<peerid>)")
	manifestPath := fs.String("manifest", "", "where to write the file manifest (default <file>.rvk.json)")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); spreads shards across discovered nodes")
	mdns := fs.Bool("mdns", false, "discover storage nodes via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("put takes exactly one <file> argument")
	}
	file := fs.Arg(0)
	outManifest := *manifestPath
	if outManifest == "" {
		outManifest = file + ".rvk.json"
	}

	cfg := pipeline.DefaultConfig()
	ctx := context.Background()
	s, closer, err := putBackend(ctx, *node, bootstrap, *mdns, cfg)
	if err != nil {
		return err
	}
	defer closer()

	m, err := runStore(ctx, s, cfg, file)
	if err != nil {
		return fmt.Errorf("store %s: %w", file, err)
	}
	data, err := encodeManifest(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outManifest, data, 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	shardCount := 0
	for _, ch := range m.Chunks {
		shardCount += len(ch.Shards)
	}
	fmt.Printf("Stored %s: %d bytes, %d chunks, %d shards\n", file, m.Size, len(m.Chunks), shardCount)
	fmt.Printf("Manifest: %s\n", outManifest)
	fmt.Fprintln(os.Stderr, "warning: the manifest contains the file's decryption keys — keep it secret, or `share` it wrapped to a recipient.")
	return nil
}

// putBackend selects the store `put` writes through. With -node it targets that
// single node (unchanged behaviour). Otherwise it joins the DHT and returns a
// PlacementStore spreading shards across discovered nodes, warning if fewer than
// k+m nodes are available (shards will then colocate, weakening the erasure
// guarantee).
func putBackend(ctx context.Context, node string, bootstrap []string, mdns bool, cfg pipeline.Config) (store.Store, func(), error) {
	switch {
	case node != "":
		return dial(ctx, node)
	case len(bootstrap) > 0 || mdns:
		ps, closer, err := dialPlacement(ctx, bootstrap, mdns)
		if err != nil {
			return nil, nil, err
		}
		if n := cfg.Params.N(); len(ps.Nodes()) < n {
			fmt.Fprintf(os.Stderr, "warning: only %d storage node(s) discovered for k+m=%d shards per chunk; shards will colocate, reducing failure-domain diversity\n", len(ps.Nodes()), n)
		} else {
			fmt.Fprintf(os.Stderr, "Placing shards across %d discovered node(s)\n", len(ps.Nodes()))
		}
		return ps, closer, nil
	default:
		return nil, nil, fmt.Errorf("provide -node <ma> to store on one node, or -bootstrap/-mdns to place across DHT-discovered nodes")
	}
}

// cmdGet reconstructs a file, via a plaintext manifest or an unwrapped shared
// cap, fetching shards from a single node (-node) or by discovering their
// providers on the DHT (-bootstrap / -mdns).
func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	node := fs.String("node", "", "fetch from this single node multiaddr (with /p2p/<peerid>)")
	manifestPath := fs.String("manifest", "", "manifest file to read (your own file)")
	capPath := fs.String("cap", "", "wrapped cap file to read (a shared file); requires -key")
	keyPath := fs.String("key", "", "your private key file, to unwrap -cap")
	out := fs.String("o", "", "output file (default stdout)")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); discovers shard providers")
	mdns := fs.Bool("mdns", false, "discover shard providers via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}

	m, err := resolveManifest(*manifestPath, *capPath, *keyPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	s, closer, err := getBackend(ctx, *node, bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := runLoad(ctx, s, m, w); err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", *out, m.Size)
	}
	return nil
}

// getBackend selects the store `get` fetches through: a single node (-node) or
// a DHT-backed store that discovers each shard's providers (-bootstrap / -mdns).
func getBackend(ctx context.Context, node string, bootstrap []string, mdns bool) (store.Store, func(), error) {
	switch {
	case node != "":
		return dial(ctx, node)
	case len(bootstrap) > 0 || mdns:
		return dialDHT(ctx, bootstrap, mdns)
	default:
		return nil, nil, fmt.Errorf("provide -node <ma> to fetch from one node, or -bootstrap/-mdns to discover providers via the DHT")
	}
}

// resolveManifest loads a manifest from either a plaintext manifest file or a
// wrapped cap file (which is unwrapped with the given private key). Exactly one
// source must be provided.
func resolveManifest(manifestPath, capPath, keyPath string) (pipeline.FileManifest, error) {
	switch {
	case manifestPath != "" && capPath != "":
		return pipeline.FileManifest{}, fmt.Errorf("use either -manifest or -cap, not both")
	case manifestPath != "":
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return pipeline.FileManifest{}, err
		}
		return decodeManifest(data)
	case capPath != "":
		if keyPath == "" {
			return pipeline.FileManifest{}, fmt.Errorf("-cap requires -key <privkey>")
		}
		return unwrapCap(capPath, keyPath)
	default:
		return pipeline.FileManifest{}, fmt.Errorf("provide -manifest <path> or -cap <path> -key <privkey>")
	}
}

func unwrapCap(capPath, keyPath string) (pipeline.FileManifest, error) {
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return pipeline.FileManifest{}, err
	}
	pub, err := priv.Public()
	if err != nil {
		return pipeline.FileManifest{}, err
	}
	sealed, err := os.ReadFile(capPath)
	if err != nil {
		return pipeline.FileManifest{}, err
	}
	data, err := cap.Unwrap(priv, pub, sealed)
	if err != nil {
		return pipeline.FileManifest{}, fmt.Errorf("unwrap cap (wrong key?): %w", err)
	}
	return decodeManifest(data)
}

// cmdShare wraps a manifest to a recipient's public key.
func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "manifest file to share")
	to := fs.String("to", "", "recipient public key (base64) or @file")
	out := fs.String("o", "", "output cap file (default <manifest>.cap)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return fmt.Errorf("missing -manifest <path>")
	}
	recipient, err := resolveRecipient(*to)
	if err != nil {
		return err
	}

	// Read the raw manifest bytes and wrap them verbatim; validate first so we
	// don't wrap garbage.
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	if _, err := decodeManifest(data); err != nil {
		return fmt.Errorf("not a valid manifest: %w", err)
	}
	sealed, err := cap.Wrap(recipient, data)
	if err != nil {
		return err
	}

	outCap := *out
	if outCap == "" {
		outCap = *manifestPath + ".cap"
	}
	if err := os.WriteFile(outCap, sealed, 0o644); err != nil {
		return fmt.Errorf("write cap: %w", err)
	}
	fmt.Printf("Wrapped %s for recipient %s\n", *manifestPath, recipient.String())
	fmt.Printf("Cap: %s\n", outCap)
	fmt.Println("Send the .cap file to the recipient; they read it with: revika-ctl get -node <ma> -cap <file> -key <their-privkey>")
	return nil
}

func readPrivateKey(path string) (cap.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return cap.PrivateKey{}, err
	}
	priv, err := cap.ParsePrivateKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return cap.PrivateKey{}, fmt.Errorf("parse private key %s: %w", path, err)
	}
	return priv, nil
}
