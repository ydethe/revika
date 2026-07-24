package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"revika/internal/cap"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// cmdKeygen generates and persists a recipient identity.
func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	prefix := fs.String("key", filepath.Join(".revika", "keys", "user"), "path prefix for the identity (writes <prefix>.key and <prefix>.pub)")
	powDifficulty := fs.Uint("pow-difficulty", 12, "proof-of-work difficulty for the signing (owner) identity, in leading zero bits (0 disables); expected cost ~2^difficulty attempts")
	powPuzzle := fs.String("pow-puzzle", "argon2id", "proof-of-work puzzle: argon2id (memory-hard, recommended) or sha256 (fast, GPU-friendly)")
	powFail := fs.Bool("pow-fail", false, "TESTING ONLY: mint a signing (owner) key that FAILS the pow check at -pow-difficulty, to exercise a node's pow-admission gate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *powDifficulty > 255 {
		return fmt.Errorf("pow-difficulty %d out of range (0-255)", *powDifficulty)
	}
	puzzle, err := cap.PuzzleByName(*powPuzzle)
	if err != nil {
		return err
	}

	privPath := *prefix + ".key"
	pubPath := *prefix + ".pub"
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing private key %s", privPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	signPrivPath := *prefix + ".sign.key"
	signPubPath := *prefix + ".sign.pub"
	if _, err := os.Stat(signPrivPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing signing key %s", signPrivPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		return err
	}
	mint := mintSigningKey
	if *powFail {
		mint = mintFailingSigningKey
	}
	signKey, signPub, err := mint(puzzle, cap.Difficulty(*powDifficulty))
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
	if err := os.WriteFile(signPrivPath, []byte(signKey.String()+"\n"), 0o600); err != nil {
		return fmt.Errorf("write signing key: %w", err)
	}
	if err := os.WriteFile(signPubPath, []byte(signPub.String()+"\n"), 0o644); err != nil {
		return fmt.Errorf("write signing public key: %w", err)
	}

	fmt.Printf("Identity written:\n")
	fmt.Printf("  encryption private: %s (keep secret — unwraps files shared to you)\n", privPath)
	fmt.Printf("  encryption public:  %s\n", pubPath)
	fmt.Printf("  signing private:    %s (keep secret — authorizes storing/deleting your shards)\n", signPrivPath)
	fmt.Printf("  signing public:     %s\n\n", signPubPath)
	fmt.Println("Public key (share this so others can send you files):")
	fmt.Println(pub.String())
	fmt.Fprintln(os.Stderr, "note: the signing key is your storage owner identity — back it up. Lose it and you cannot delete or renew what you stored (the data is still retrievable via its manifest).")
	return nil
}

// mintSigningKey grinds a self-certifying owner identity, rendering an
// ssh-keygen-style progress line on stderr when it is a terminal (and a quiet
// one-shot summary otherwise, e.g. when logging to a file or in CI).
func mintSigningKey(puzzle cap.Puzzle, d cap.Difficulty) (cap.SignKey, cap.SignPubKey, error) {
	if d == 0 {
		// Proof-of-work disabled: a plain keypair, no grinding.
		return cap.GenerateSigningKey()
	}

	tty := isTerminal(os.Stderr)
	expected := 1 << uint(d) // ~2^d attempts expected
	fmt.Fprintf(os.Stderr, "Minting owner identity: %s, difficulty %d bits (~%s attempts expected)\n",
		puzzle.Name(), d, humanCount(uint64(expected)))

	var final cap.Progress
	onProgress := func(p cap.Progress) {
		final = p
		if !tty {
			return
		}
		rate := 0.0
		if s := p.Elapsed.Seconds(); s > 0 {
			rate = float64(p.Attempts) / s
		}
		line := fmt.Sprintf("%s  %s attempts  %s/s  %s",
			spinner(p.Elapsed), humanCount(p.Attempts), humanCount(uint64(rate)),
			progressBar(p.Attempts, uint64(expected)))
		// Overwrite in place; pad to clear any shorter previous line.
		fmt.Fprintf(os.Stderr, "\r%-72s", line)
	}

	signKey, signPub, err := cap.MintSigningKey(puzzle, d, onProgress)
	if tty {
		fmt.Fprintln(os.Stderr) // finish the progress line
	}
	if err != nil {
		return cap.SignKey{}, cap.SignPubKey{}, err
	}
	fmt.Fprintf(os.Stderr, "Minted owner identity after %s attempts in %s.\n",
		humanCount(final.Attempts), roundDuration(final.Elapsed))
	return signKey, signPub, nil
}

// mintFailingSigningKey is the deliberate inverse of mintSigningKey: it returns a
// signing (owner) keypair whose public key does NOT satisfy puzzle at difficulty
// d — a non-self-certifying identity that a pow-enforcing node refuses on write.
// It exists only for testing that admission gate; a random Ed25519 key fails
// difficulty d with probability 1 - 2^-d, so this returns almost immediately.
// At d == 0 no key can fail (every key passes), which is an error.
func mintFailingSigningKey(puzzle cap.Puzzle, d cap.Difficulty) (cap.SignKey, cap.SignPubKey, error) {
	if d == 0 {
		return cap.SignKey{}, cap.SignPubKey{}, fmt.Errorf("-pow-fail needs -pow-difficulty > 0: at difficulty 0 every key passes, so none can fail")
	}
	for range 1_000_000 {
		key, pub, err := cap.GenerateSigningKey()
		if err != nil {
			return cap.SignKey{}, cap.SignPubKey{}, err
		}
		if !cap.MeetsPoW(puzzle, pub[:], d) {
			fmt.Fprintf(os.Stderr, "TESTING: minted a NON-self-certifying owner identity failing %s at difficulty %d bits — a pow-enforcing node will reject its writes.\n", puzzle.Name(), d)
			return key, pub, nil
		}
	}
	return cap.SignKey{}, cap.SignPubKey{}, fmt.Errorf("could not find a key failing difficulty %d after 1e6 attempts", d)
}

// defaultSignKeyPath is where put/delete look for the User's signing key.
const defaultSignKeyPath = ".revika/keys/user.sign.key"

// loadSignKey reads the User's Ed25519 signing key from path.
func loadSignKey(path string) (cap.SignKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cap.SignKey{}, fmt.Errorf("signing key %s not found; run `revika-ctl keygen` first (or pass -signkey)", path)
		}
		return cap.SignKey{}, err
	}
	k, err := cap.ParseSignKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return cap.SignKey{}, fmt.Errorf("parse signing key %s: %w", path, err)
	}
	return k, nil
}

// cmdPut stores a file and writes its manifest. It targets either a single node
// (-node) or, via the DHT, a set of discovered nodes across which the shards are
// spread (-bootstrap / -mdns).
func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	node := fs.String("node", "", "store on this single node multiaddr (with /p2p/<peerid>)")
	manifestPath := fs.String("manifest", "", "where to write the file manifest (default <file>.rvk.json)")
	signKeyPath := fs.String("signkey", defaultSignKeyPath, "your signing key, authorizing the store")
	grantTTL := fs.Duration("grant-ttl", 0, "expiry of the repair grants attached to shards (0 = never expire)")
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

	signer, err := loadSignKey(*signKeyPath)
	if err != nil {
		return err
	}

	cfg := pipeline.DefaultConfig()
	var grantExpiry int64
	if *grantTTL > 0 {
		grantExpiry = time.Now().Add(*grantTTL).Unix()
	}
	ctx := context.Background()
	s, closer, err := putBackend(ctx, *node, bootstrap, *mdns, cfg, signer, grantExpiry)
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
func putBackend(ctx context.Context, node string, bootstrap []string, mdns bool, cfg pipeline.Config, signer cap.SignKey, grantExpiry int64) (store.Store, func(), error) {
	switch {
	case node != "":
		return dialSigned(ctx, node, signer)
	case len(bootstrap) > 0 || mdns:
		ps, closer, err := dialPlacement(ctx, bootstrap, mdns, signer)
		if err != nil {
			return nil, nil, err
		}
		ps.SetGrantExpiry(grantExpiry)
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
	out := fs.String("o", "", "output file (default: the file's original name from the manifest, or stdout if it carries none)")
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

	// Choose the output path: an explicit -o wins; otherwise fall back to the
	// original file name recorded in the manifest, using just its base so a
	// manifest can't steer the write outside the current directory. Only when
	// neither is available do we stream to stdout.
	outPath := *out
	if outPath == "" && m.Name != "" {
		outPath = filepath.Base(m.Name)
	}

	w := os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := runLoad(ctx, s, m, w); err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}
	if outPath != "" {
		fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", outPath, m.Size)
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

// cmdDelete removes the shards of a file this User stored. It drops only the
// caller's ownership claim on each shard (a node frees the bytes once its last
// owner leaves), so deleting never affects another User's copy of shared data.
func cmdDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	node := fs.String("node", "", "delete from this single node multiaddr (with /p2p/<peerid>)")
	manifestPath := fs.String("manifest", "", "manifest of the file to delete")
	signKeyPath := fs.String("signkey", defaultSignKeyPath, "your signing key, authorizing the delete")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); finds shard providers")
	mdns := fs.Bool("mdns", false, "discover shard providers via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return fmt.Errorf("missing -manifest <path>")
	}

	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	m, err := decodeManifest(data)
	if err != nil {
		return err
	}
	signer, err := loadSignKey(*signKeyPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	// Delete attaches no repair grants, so the grant-expiry argument is unused.
	s, closer, err := putBackend(ctx, *node, bootstrap, *mdns, m.Params, signer, 0)
	if err != nil {
		return err
	}
	defer closer()

	var deleted, missing, failed int
	for _, ch := range m.Chunks {
		for _, id := range ch.Shards {
			switch err := s.Delete(ctx, id); {
			case err == nil:
				deleted++
			case errors.Is(err, store.ErrNotFound):
				missing++
			default:
				failed++
				fmt.Fprintf(os.Stderr, "delete %s: %v\n", id, err)
			}
		}
	}
	fmt.Printf("Deleted %d shard(s); %d already absent, %d failed\n", deleted, missing, failed)
	if failed > 0 {
		return fmt.Errorf("%d shard(s) could not be deleted", failed)
	}
	return nil
}

// cmdNodes lists the storage nodes the client can discover on the DHT — the
// nodes it is "aware of" and could place shards on. It joins the network via
// -bootstrap/-mdns exactly like put/get, then reports each advertised node with
// its peer ID, whether we could reach it, and its advertised addresses.
func cmdNodes(args []string) error {
	fs := flag.NewFlagSet("nodes", flag.ExitOnError)
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable)")
	mdns := fs.Bool("mdns", false, "discover storage nodes via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	h, disc, closer, err := joinDHT(ctx, bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	nodes := discoverNodeInfos(ctx, h, disc)
	if len(nodes) == 0 {
		fmt.Println("No storage nodes discovered via the DHT.")
		return nil
	}

	reachable := 0
	for _, n := range nodes {
		if n.Reachable {
			reachable++
		}
	}
	fmt.Printf("Discovered %d storage node(s) via the DHT (%d reachable):\n", len(nodes), reachable)
	for _, n := range nodes {
		status := "unreachable"
		if n.Reachable {
			status = "reachable"
		}
		addrs := make([]string, 0, len(n.Info.Addrs))
		for _, a := range n.Info.Addrs {
			addrs = append(addrs, a.String())
		}
		fmt.Printf("  %s  %-11s  %s\n", n.Info.ID, status, strings.Join(addrs, ", "))
	}
	return nil
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
