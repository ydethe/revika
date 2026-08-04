package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// cmdKeygen generates and persists a recipient identity.
//
// Defence controls (security/Defence.md; primitives P24, P9 in security/frameworks.md):
//
//	SC-12 (Cryptographic Key Establishment and Management) / SC-28 (Protection of Information at
//	      Rest) — private keys are written 0600 under a 0700 dir and never leave the machine.
//	SC-5  (Denial-of-Service Protection) — the signing key is ground via proof-of-work so a banned
//	      owner identity cannot be cheaply re-minted (anti-Sybil floor).
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
	manifestPath := fs.String("manifest", "", "where to write the file manifest / directory root cap (default <file>.rvk.json)")
	signKeyPath := fs.String("signkey", defaultSignKeyPath, "your signing key, authorizing the store")
	grantTTL := fs.Duration("grant-ttl", 0, "expiry of the repair grants attached to shards (0 = never expire)")
	recursive := fs.Bool("r", false, "store <file> as a directory tree (Merkle DAG of cap-addressed blobs); writes the root cap to -manifest")
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

	if *recursive {
		return putTree(ctx, s, cfg, file, outManifest)
	}

	start := time.Now()
	m, err := runStore(ctx, s, cfg, file)
	if err != nil {
		return fmt.Errorf("store %s: %w", file, err)
	}
	elapsed := time.Since(start)
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
	throughputMBps := (float64(m.Size) / (1024 * 1024)) / elapsed.Seconds()
	fmt.Printf("Transferred to revika in %s (~%.2f MB/s)\n", elapsed.Round(time.Millisecond), throughputMBps)
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

// cmdGet reconstructs what a capability addresses — a single file or a whole
// directory tree — fetching shards from a single node (-node) or by discovering
// their providers on the DHT (-bootstrap / -mdns). The source is either the
// User's own plaintext manifest/root-cap (-manifest) or a shared, wrapped cap
// (-cap, unwrapped with -key). Whether it is a file or a directory is decided by
// the capability itself (its Kind), so a recipient need not know in advance
// which they were sent — including a single file or subtree carved out of a tree
// with `share -path`; -r stays accepted as an explicit hint.
func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	node := fs.String("node", "", "fetch from this single node multiaddr (with /p2p/<peerid>)")
	manifestPath := fs.String("manifest", "", "manifest / directory root cap file to read (your own data)")
	capPath := fs.String("cap", "", "wrapped cap file to read (a shared file/tree); requires -key")
	keyPath := fs.String("key", "", "your private key file, to unwrap -cap")
	out := fs.String("o", "", "output file (default: the file's original name from the manifest, or stdout if it carries none); for a directory, the destination directory (required)")
	recursive := fs.Bool("r", false, "expect a directory tree (into -o); the capability's kind is auto-detected, so this is only a hint")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); discovers shard providers")
	mdns := fs.Bool("mdns", false, "discover shard providers via mDNS on the LAN")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	s, closer, err := getBackend(ctx, *node, bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	// Resolve the capability to exactly one of: a directory root/subtree cap
	// (tree restore) or a file manifest (single-file restore). A -cap is
	// unwrapped and its Kind sniffed here.
	fm, dirCap, err := resolveGetTarget(ctx, s, *manifestPath, *capPath, *keyPath)
	if err != nil {
		return err
	}

	if dirCap != nil {
		if *out == "" {
			return fmt.Errorf("restoring a directory needs -o <destination directory>")
		}
		return getTree(ctx, s, *dirCap, *out)
	}
	if *recursive {
		return fmt.Errorf("-r expects a directory tree, but this capability is a single file; drop -r")
	}
	m := *fm

	// Choose the output path: an explicit -o wins; otherwise fall back to the
	// original file name recorded in the manifest, using just its base so a
	// manifest can't steer the write outside the current directory. Only when
	// neither is available do we stream to stdout.
	outPath := *out
	if outPath == "" && m.Name != "" {
		outPath = filepath.Base(m.Name)
	}

	// No output path: stream the bytes to stdout; there is nowhere to restore
	// filesystem metadata to, so it is ignored.
	if outPath == "" {
		if err := runLoad(ctx, s, m, os.Stdout); err != nil {
			return fmt.Errorf("retrieve: %w", err)
		}
		return nil
	}

	// A symlink's content is its target path (recorded in the manifest as
	// metadata, §3.8), so recreate the link rather than writing a file.
	if m.Meta.IsSymlink() {
		if err := restoreSymlink(outPath, m.Meta); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Wrote symlink %s -> %s\n", outPath, m.Meta.SymlinkTarget)
		return nil
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	if err := runLoad(ctx, s, m, f); err != nil {
		f.Close()
		return fmt.Errorf("retrieve: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Restore mode/times/owner/xattrs after the content is fully written and
	// closed; a partial restore (e.g. chown without privilege) warns but does
	// not fail the retrieval.
	if err := restoreMetadata(outPath, m.Meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial metadata restore for %s: %v\n", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", outPath, m.Size)
	return nil
}

// restoreSymlink recreates the symbolic link described by meta at path,
// replacing any existing entry, then restores its ownership/xattrs.
func restoreSymlink(path string, meta pipeline.Metadata) error {
	if meta.SymlinkTarget == "" {
		return fmt.Errorf("manifest marks a symlink but carries no target")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(meta.SymlinkTarget, path); err != nil {
		return fmt.Errorf("recreate symlink: %w", err)
	}
	if err := restoreMetadata(path, meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial metadata restore for %s: %v\n", path, err)
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

// resolveGetTarget resolves the flags of `get` to exactly one of a file manifest
// (single-file restore) or a directory root/subtree cap (tree restore). The
// source is a plaintext -manifest (the User's own file manifest or directory
// root cap) or a wrapped -cap unwrapped with -key (a shared single file, whole
// subtree, or a legacy file manifest). In every case the capability's own Kind —
// not a flag — decides which it is; a KindFile cap is hydrated into its file
// manifest via the store s, a KindDir cap is returned for getTree to walk.
func resolveGetTarget(ctx context.Context, s store.Store, manifestPath, capPath, keyPath string) (*pipeline.FileManifest, *manifest.ReadCap, error) {
	var raw []byte
	switch {
	case manifestPath != "" && capPath != "":
		return nil, nil, fmt.Errorf("use either -manifest or -cap, not both")
	case manifestPath != "":
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, nil, err
		}
		raw = data
	case capPath != "":
		if keyPath == "" {
			return nil, nil, fmt.Errorf("-cap requires -key <privkey>")
		}
		data, err := unwrapCapBytes(capPath, keyPath)
		if err != nil {
			return nil, nil, err
		}
		raw = data
	default:
		return nil, nil, fmt.Errorf("provide -manifest <path> or -cap <path> -key <privkey>")
	}

	// A cap-addressed blob capability (a directory root/subtree, or a single file
	// carved from a tree by `share -path`) carries a "kind"; a legacy plaintext
	// file manifest does not. Route on that.
	if looksLikeReadCap(raw) {
		var c manifest.ReadCap
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, nil, fmt.Errorf("parse cap: %w", err)
		}
		switch c.Kind {
		case manifest.KindDir:
			return nil, &c, nil
		case manifest.KindFile:
			m, err := manifest.LoadFileManifest(ctx, s, c)
			if err != nil {
				return nil, nil, err
			}
			return &m, nil, nil
		default:
			return nil, nil, fmt.Errorf("capability has unknown kind %s", c.Kind)
		}
	}

	m, err := decodeManifest(raw)
	if err != nil {
		return nil, nil, err
	}
	return &m, nil, nil
}

// looksLikeReadCap reports whether data is a serialized manifest.ReadCap (a
// cap-addressed file/directory capability) rather than a legacy plaintext file
// manifest. A ReadCap always carries a "kind" and "shards"; a file manifest
// carries "chunks" and no "kind". Sniffing lets a recipient of a -cap not have
// to know in advance which they were sent.
func looksLikeReadCap(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	_, hasKind := probe["kind"]
	_, hasShards := probe["shards"]
	return hasKind && hasShards
}

// unwrapCapBytes unwraps the sealed cap file at capPath with the private key at
// keyPath, returning the raw plaintext bytes (a ReadCap or a legacy manifest).
func unwrapCapBytes(capPath, keyPath string) ([]byte, error) {
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	pub, err := priv.Public()
	if err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(capPath)
	if err != nil {
		return nil, err
	}
	data, err := cap.Unwrap(priv, pub, sealed)
	if err != nil {
		return nil, fmt.Errorf("unwrap cap (wrong key?): %w", err)
	}
	return data, nil
}

// shareResult is the outcome of building a shareable cap: the sealed bytes plus
// the Kind the recipient will receive, so the printed `get` hint matches.
type shareResult struct {
	sealed []byte
	kind   manifest.Kind
}

// cmdShare wraps a read-capability to a recipient's public key so only they can
// open it. The -manifest source may be a single-file manifest (from `put`) or a
// directory root cap (from `put -r`); with -path it shares only the file or
// subdirectory at that slash-separated path within a tree, resolving it through
// a -node/-bootstrap/-mdns backend. Sharing a directory cap grants read access
// to that whole subtree and nothing outside it (§3.5).
func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "manifest or directory root cap to share")
	to := fs.String("to", "", "recipient public key (base64) or @file")
	out := fs.String("o", "", "output cap file (default <manifest>.cap)")
	path := fs.String("path", "", "share only the file or subdirectory at this slash-separated path within a directory root cap (needs a -node/-bootstrap/-mdns backend to resolve)")
	node := fs.String("node", "", "resolve -path via this single node multiaddr")
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); resolves -path via the DHT")
	mdns := fs.Bool("mdns", false, "discover shard providers via mDNS to resolve -path")
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
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}

	// Only resolving a subpath touches the network; wrapping a whole manifest or
	// root cap is a purely local operation.
	ctx := context.Background()
	var s store.Store
	if *path != "" {
		var closer func()
		s, closer, err = getBackend(ctx, *node, bootstrap, *mdns)
		if err != nil {
			return fmt.Errorf("share -path needs a backend to resolve the tree: %w", err)
		}
		defer closer()
	}

	res, err := buildShareCap(ctx, s, recipient, data, *path)
	if err != nil {
		return err
	}

	outCap := *out
	if outCap == "" {
		outCap = *manifestPath + ".cap"
	}
	if err := os.WriteFile(outCap, res.sealed, 0o644); err != nil {
		return fmt.Errorf("write cap: %w", err)
	}

	what := *manifestPath
	if *path != "" {
		what = fmt.Sprintf("%s in %s", *path, *manifestPath)
	}
	fmt.Printf("Wrapped %s [%s] for recipient %s\n", what, res.kind, recipient.String())
	fmt.Printf("Cap: %s\n", outCap)
	if res.kind == manifest.KindDir {
		fmt.Println("Send the .cap file to the recipient; they read the subtree with: revika-ctl get -node <ma> -cap <file> -key <their-privkey> -o <dir>")
	} else {
		fmt.Println("Send the .cap file to the recipient; they read it with: revika-ctl get -node <ma> -cap <file> -key <their-privkey>")
	}
	return nil
}

// buildShareCap produces the sealed bytes to hand a recipient for the given
// source manifest bytes and optional subpath. With a subpath it resolves the
// child cap through s (which must be non-nil), wrapping just that file or
// subtree; otherwise it wraps the whole source — a directory root cap or a
// legacy single-file manifest — with no network contact. It reports which Kind
// the recipient receives.
func buildShareCap(ctx context.Context, s store.Store, recipient cap.PublicKey, data []byte, path string) (shareResult, error) {
	if path != "" {
		if !looksLikeReadCap(data) {
			return shareResult{}, fmt.Errorf("-path can only be used with a directory root cap (from `put -r`); this looks like a single-file manifest")
		}
		var root manifest.ReadCap
		if err := json.Unmarshal(data, &root); err != nil {
			return shareResult{}, fmt.Errorf("parse root cap: %w", err)
		}
		child, err := manifest.Resolve(ctx, s, root, path)
		if err != nil {
			return shareResult{}, fmt.Errorf("resolve %q: %w", path, err)
		}
		sealed, err := manifest.WrapCap(recipient, child)
		if err != nil {
			return shareResult{}, err
		}
		return shareResult{sealed: sealed, kind: child.Kind}, nil
	}

	// No subpath: wrap the whole source. A directory root cap is wrapped as a
	// ReadCap (granting the entire subtree); a legacy single-file manifest is
	// wrapped verbatim for backward compatibility.
	if looksLikeReadCap(data) {
		var c manifest.ReadCap
		if err := json.Unmarshal(data, &c); err != nil {
			return shareResult{}, fmt.Errorf("parse root cap: %w", err)
		}
		sealed, err := manifest.WrapCap(recipient, c)
		if err != nil {
			return shareResult{}, err
		}
		return shareResult{sealed: sealed, kind: c.Kind}, nil
	}

	if _, err := decodeManifest(data); err != nil {
		return shareResult{}, fmt.Errorf("not a valid manifest: %w", err)
	}
	sealed, err := cap.Wrap(recipient, data)
	if err != nil {
		return shareResult{}, err
	}
	return shareResult{sealed: sealed, kind: manifest.KindFile}, nil
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
