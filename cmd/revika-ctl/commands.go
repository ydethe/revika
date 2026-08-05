package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/provider"
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

// defaultSignKeyPath is where cp/rm/share look for the User's signing key.
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

// --- namespace addressing -------------------------------------------------

// rvkScheme prefixes an address that names the namespace rather than the local
// filesystem, e.g. rvk:docs/report.pdf.
const rvkScheme = "rvk:"

// defaultRootPath is where a User's namespace anchor lives when neither -root nor
// $REVIKA_ROOT is set.
const defaultRootPath = ".revika/root.json"

// isRvk reports whether s addresses the namespace (carries the rvk: scheme).
func isRvk(s string) bool { return strings.HasPrefix(s, rvkScheme) }

// rvkPath strips the rvk: scheme, returning the slash-separated namespace path
// (empty for the root itself).
func rvkPath(s string) string { return strings.TrimPrefix(s, rvkScheme) }

// rootPath resolves the namespace anchor file to use: the -root flag if set, else
// $REVIKA_ROOT, else the default .revika/root.json.
func rootPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("REVIKA_ROOT"); env != "" {
		return env
	}
	return defaultRootPath
}

// loadRoot reads the namespace anchor at file. It returns the current signed
// RootPointer, whether the file existed (a fresh namespace when false), and
// whether it was a *sealed* shared root (read-only, opened with -key). A
// plaintext (owned) root is RootPointer JSON; a shared root is that JSON sealed
// to the recipient with ML-KEM-768 (opaque bytes), so a JSON-parse failure
// routes to the sealed path. In both cases the signature is verified.
func loadRoot(file, keyPath string) (rp manifest.RootPointer, exists, sealed bool, err error) {
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return manifest.RootPointer{}, false, false, nil
		}
		return manifest.RootPointer{}, false, false, err
	}
	if rp, derr := provider.DecodeRootPointer(data); derr == nil {
		if !rp.Verify() {
			return manifest.RootPointer{}, false, false, fmt.Errorf("root %s failed signature verification", file)
		}
		return rp, true, false, nil
	}
	// Not plaintext JSON: treat as a sealed shared root, opened with -key.
	if keyPath == "" {
		return manifest.RootPointer{}, false, false, fmt.Errorf("root %s looks like a sealed shared root; pass -key <privkey> to open it", file)
	}
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return manifest.RootPointer{}, false, false, err
	}
	pub, err := priv.Public()
	if err != nil {
		return manifest.RootPointer{}, false, false, err
	}
	raw, err := cap.Unwrap(priv, pub, data)
	if err != nil {
		return manifest.RootPointer{}, false, false, fmt.Errorf("open sealed root %s (wrong key?): %w", file, err)
	}
	rp, err = provider.DecodeRootPointer(raw)
	if err != nil {
		return manifest.RootPointer{}, false, false, err
	}
	if !rp.Verify() {
		return manifest.RootPointer{}, false, false, fmt.Errorf("sealed root %s failed signature verification", file)
	}
	return rp, true, true, nil
}

// currentRoot returns the root-directory cap to operate on, creating (and
// storing) an empty root when the namespace is fresh.
func currentRoot(ctx context.Context, s store.Store, cfg pipeline.Config, prev manifest.RootPointer, exists bool) (manifest.ReadCap, error) {
	if exists {
		return prev.Root, nil
	}
	return manifest.StoreDir(ctx, s, cfg, manifest.NewDir(pipeline.Metadata{}))
}

// commitRoot signs a RootPointer advancing the namespace to newRoot and saves it
// to the owned root file. Seq starts at 1 for a fresh namespace, else advances
// the previous one. It refuses to modify a sealed (shared) or foreign-owned root.
func commitRoot(ctx context.Context, file string, signer cap.SignKey, newRoot manifest.ReadCap, prev manifest.RootPointer, exists, sealed bool) error {
	if sealed {
		return fmt.Errorf("root %s is a shared, read-only root (sealed to you); it cannot be modified", file)
	}
	if exists && prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", file)
	}
	seq := uint64(1)
	if exists {
		seq = prev.Seq + 1
	}
	rp, err := manifest.SignRoot(signer, newRoot, seq, time.Now().UnixNano())
	if err != nil {
		return err
	}
	return provider.NewFileRootStore(file).Save(ctx, rp)
}

// --- backends -------------------------------------------------------------

// addBackendFlags registers the shared node/DHT selection flags on fs.
func addBackendFlags(fs *flag.FlagSet) (node *string, bootstrap *multiFlag, mdns *bool) {
	node = fs.String("node", "", "use this single node multiaddr (with /p2p/<peerid>)")
	bootstrap = &multiFlag{}
	fs.Var(bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); use the DHT instead of one node")
	mdns = fs.Bool("mdns", false, "discover nodes via mDNS on the LAN")
	return
}

// readBackend selects a read store: a single node (-node) or a DHT-backed store
// that discovers each shard's providers (-bootstrap / -mdns).
func readBackend(ctx context.Context, node string, bootstrap []string, mdns bool) (store.Store, func(), error) {
	switch {
	case node != "":
		return dial(ctx, node)
	case len(bootstrap) > 0 || mdns:
		return dialDHT(ctx, bootstrap, mdns)
	default:
		return nil, nil, fmt.Errorf("provide -node <ma>, or -bootstrap/-mdns to use the DHT")
	}
}

// writeBackend selects a read+write store the namespace is mutated through. With
// -node it targets that single node (a NetStore does Get/Put/Delete); otherwise
// it joins the DHT and returns a PlacementStore, which spreads new shards across
// discovered nodes while still reading directory blobs back via the DHT.
func writeBackend(ctx context.Context, node string, bootstrap []string, mdns bool, signer cap.SignKey, grantExpiry int64, cfg pipeline.Config) (store.Store, func(), error) {
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
		return nil, nil, fmt.Errorf("provide -node <ma>, or -bootstrap/-mdns to use the DHT")
	}
}

// --- cp -------------------------------------------------------------------

// cmdCp copies between the local filesystem and the namespace, scp-style:
// exactly one of <src>/<dst> carries the rvk: prefix. Storing grafts the local
// file or subtree into the -root and advances its signed sequence; retrieving
// resolves the rvk: path and reconstructs it locally.
func cmdCp(args []string) error {
	fs := flag.NewFlagSet("cp", flag.ExitOnError)
	node, bootstrap, mdns := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "namespace root file (default $REVIKA_ROOT, else "+defaultRootPath+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root")
	signKeyPath := fs.String("signkey", defaultSignKeyPath, "your signing key, authorizing writes into your namespace")
	grantTTL := fs.Duration("grant-ttl", 0, "expiry of the repair grants attached to stored shards (0 = never)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("cp takes <src> <dst>; exactly one carries the rvk: prefix")
	}
	src, dst := fs.Arg(0), fs.Arg(1)
	rootFile := rootPath(*rootFlag)
	ctx := context.Background()

	switch {
	case isRvk(dst) && !isRvk(src):
		return cpStore(ctx, rootFile, src, rvkPath(dst), *keyPath, *signKeyPath, *node, *bootstrap, *mdns, *grantTTL)
	case isRvk(src) && !isRvk(dst):
		return cpRetrieve(ctx, rootFile, rvkPath(src), dst, *keyPath, *node, *bootstrap, *mdns)
	case isRvk(src) && isRvk(dst):
		return fmt.Errorf("cp between two rvk: paths is not supported; retrieve to a local path, then store")
	default:
		return fmt.Errorf("cp needs exactly one rvk: path, e.g. `cp file rvk:dir/` (store) or `cp rvk:dir/file .` (retrieve)")
	}
}

// cpStore stores the local src (a file, symlink, or directory) into the
// namespace at dstRvk, grafting it into the -root and committing an advanced
// RootPointer.
func cpStore(ctx context.Context, rootFile, src, dstRvk, keyPath, signKeyPath, node string, bootstrap []string, mdns bool, grantTTL time.Duration) error {
	signer, err := loadSignKey(signKeyPath)
	if err != nil {
		return err
	}
	prev, exists, sealed, err := loadRoot(rootFile, keyPath)
	if err != nil {
		return err
	}
	if sealed {
		return fmt.Errorf("cannot store into a shared, read-only root (%s)", rootFile)
	}
	if exists && prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", rootFile)
	}

	cfg := pipeline.DefaultConfig()
	var grantExpiry int64
	if grantTTL > 0 {
		grantExpiry = time.Now().Add(grantTTL).Unix()
	}
	s, closer, err := writeBackend(ctx, node, bootstrap, mdns, signer, grantExpiry, cfg)
	if err != nil {
		return err
	}
	defer closer()

	root, err := currentRoot(ctx, s, cfg, prev, exists)
	if err != nil {
		return err
	}

	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	var (
		child manifest.ReadCap
		stat  manifest.StatCache
		label string
	)
	if fi.IsDir() {
		c, _, serr := storeTree(ctx, s, cfg, src)
		if serr != nil {
			return fmt.Errorf("store %s: %w", src, serr)
		}
		child = c
		stat = manifest.StatCache{Kind: manifest.KindDir, Mode: uint32(fi.Mode())}
		label = "directory " + src
	} else {
		fm, serr := runStore(ctx, s, cfg, src)
		if serr != nil {
			return fmt.Errorf("store %s: %w", src, serr)
		}
		c, serr := manifest.StoreFileManifest(ctx, s, cfg, fm)
		if serr != nil {
			return serr
		}
		child = c
		stat = statFromManifest(fm)
		label = src
	}

	dstPath := destPath(ctx, s, root, dstRvk, filepath.Base(src))
	newRoot, err := manifest.Graft(ctx, s, cfg, root, dstPath, child, stat)
	if err != nil {
		return fmt.Errorf("graft rvk:%s: %w", dstPath, err)
	}
	if err := commitRoot(ctx, rootFile, signer, newRoot, prev, exists, sealed); err != nil {
		return err
	}
	fmt.Printf("Stored %s -> rvk:%s\n", label, dstPath)
	return nil
}

// destPath maps a cp destination rvk path to the namespace path a child is
// grafted at, following cp/scp semantics: an empty path (rvk:), a trailing
// slash, or a path that already names a directory means "into that directory
// under the source's base name"; anything else is the full target path (store
// and rename).
func destPath(ctx context.Context, s store.Store, root manifest.ReadCap, dst, base string) string {
	if dst == "" {
		return base
	}
	if trimmed, ok := strings.CutSuffix(dst, "/"); ok {
		return path.Join(trimmed, base)
	}
	if c, err := manifest.Resolve(ctx, s, root, dst); err == nil && c.Kind == manifest.KindDir {
		return path.Join(dst, base)
	}
	return dst
}

// cpRetrieve reconstructs what srcRvk addresses (a file or a subtree) into the
// local dst. Writing into an existing local directory keeps the source's base
// name; otherwise dst is the literal output path.
func cpRetrieve(ctx context.Context, rootFile, srcRvk, dst, keyPath, node string, bootstrap []string, mdns bool) error {
	prev, exists, _, err := loadRoot(rootFile, keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to retrieve", rootFile)
	}
	s, closer, err := readBackend(ctx, node, bootstrap, mdns)
	if err != nil {
		return err
	}
	defer closer()

	c, err := manifest.Resolve(ctx, s, prev.Root, srcRvk)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", srcRvk, err)
	}

	target := dst
	if fi, serr := os.Stat(dst); serr == nil && fi.IsDir() {
		base := path.Base(srcRvk)
		if base == "." || base == "/" || base == "" {
			return fmt.Errorf("cannot retrieve the namespace root into %s without a name; give an explicit output path", dst)
		}
		target = filepath.Join(dst, base)
	}

	switch c.Kind {
	case manifest.KindDir:
		n, err := restoreTree(ctx, s, c, target)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Restored %d file(s) into %s\n", n, target)
		return nil
	case manifest.KindFile:
		if parent := filepath.Dir(target); parent != "" && parent != "." {
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return err
			}
		}
		if _, err := restoreFile(ctx, s, c, target); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Wrote %s\n", target)
		return nil
	default:
		return fmt.Errorf("rvk:%s has unknown kind %s", srcRvk, c.Kind)
	}
}

// --- ls -------------------------------------------------------------------

// cmdLs lists a directory in the namespace, reading directory blobs only (no
// file content). Plain output is one name per line (directories end in /); -l
// adds kind/size/mtime and -R recurses.
func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	node, bootstrap, mdns := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "namespace root file (default $REVIKA_ROOT, else "+defaultRootPath+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root")
	long := fs.Bool("l", false, "long format: kind, size, and mtime per entry")
	recurse := fs.Bool("R", false, "list subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target := ""
	switch fs.NArg() {
	case 0:
	case 1:
		if !isRvk(fs.Arg(0)) {
			return fmt.Errorf("ls takes an rvk: path (or none for the root)")
		}
		target = rvkPath(fs.Arg(0))
	default:
		return fmt.Errorf("ls takes at most one rvk: path")
	}

	rootFile := rootPath(*rootFlag)
	prev, exists, _, err := loadRoot(rootFile, *keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to list", rootFile)
	}

	ctx := context.Background()
	s, closer, err := readBackend(ctx, *node, *bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	c, err := manifest.Resolve(ctx, s, prev.Root, target)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", target, err)
	}
	if c.Kind != manifest.KindDir {
		// ls on a single file lists just that file (coreutils behaviour).
		printLsEntry(os.Stdout, path.Base(target), manifest.StatCache{Kind: c.Kind}, *long)
		return nil
	}
	return lsDir(ctx, s, c, target, *long, *recurse)
}

// lsDir lists the entries of the directory addressed by dirCap. With recurse it
// then descends into each subdirectory, printing a "rvk:<path>:" header before
// each (coreutils ls -R style).
func lsDir(ctx context.Context, s store.Store, dirCap manifest.ReadCap, name string, long, recurse bool) error {
	d, err := manifest.LoadDir(ctx, s, dirCap)
	if err != nil {
		return err
	}
	if recurse {
		fmt.Printf("%s%s:\n", rvkScheme, name)
	}
	for _, e := range d.Entries {
		printLsEntry(os.Stdout, e.Name, e.Stat, long)
	}
	if recurse {
		for _, e := range d.Entries {
			if e.Cap.Kind == manifest.KindDir {
				fmt.Println()
				if err := lsDir(ctx, s, e.Cap, path.Join(name, e.Name), long, recurse); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// printLsEntry writes one listing line for name with cached stat st. Plain form
// is the name (directories suffixed /); long form prefixes kind, size and mtime.
func printLsEntry(w io.Writer, name string, st manifest.StatCache, long bool) {
	display := name
	if st.Kind == manifest.KindDir {
		display += "/"
	}
	if !long {
		fmt.Fprintln(w, display)
		return
	}
	kind := "f"
	if st.Kind == manifest.KindDir {
		kind = "d"
	}
	mtime := "-"
	if st.ModTimeNS != 0 {
		mtime = time.Unix(0, st.ModTimeNS).Format("2006-01-02 15:04")
	}
	fmt.Fprintf(w, "%s %12d  %-16s  %s\n", kind, st.Size, mtime, display)
}

// --- rm -------------------------------------------------------------------

// cmdRm removes an rvk: path (a file or a whole subtree) from the -root and drops
// the caller's ownership claim on its shards. A node frees a shard's bytes only
// once its last owner leaves, so this never affects another User's shared copy.
func cmdRm(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	node, bootstrap, mdns := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "namespace root file (default $REVIKA_ROOT, else "+defaultRootPath+")")
	signKeyPath := fs.String("signkey", defaultSignKeyPath, "your signing key, authorizing the delete")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || !isRvk(fs.Arg(0)) {
		return fmt.Errorf("rm takes one rvk:<path>")
	}
	target := rvkPath(fs.Arg(0))
	if target == "" {
		return fmt.Errorf("refusing to remove the namespace root itself")
	}

	rootFile := rootPath(*rootFlag)
	signer, err := loadSignKey(*signKeyPath)
	if err != nil {
		return err
	}
	prev, exists, sealed, err := loadRoot(rootFile, "")
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to remove", rootFile)
	}
	if sealed {
		return fmt.Errorf("cannot remove from a shared, read-only root (%s)", rootFile)
	}
	if prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", rootFile)
	}

	ctx := context.Background()
	cfg := pipeline.DefaultConfig()
	s, closer, err := writeBackend(ctx, *node, *bootstrap, *mdns, signer, 0, cfg)
	if err != nil {
		return err
	}
	defer closer()

	victim, err := manifest.Resolve(ctx, s, prev.Root, target)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", target, err)
	}
	shards := map[store.ShardID]struct{}{}
	if err := collectShards(ctx, s, victim, shards); err != nil {
		return fmt.Errorf("enumerate shards of rvk:%s: %w", target, err)
	}

	newRoot, err := manifest.GraftRemove(ctx, s, cfg, prev.Root, target)
	if err != nil {
		return fmt.Errorf("remove rvk:%s: %w", target, err)
	}
	if err := commitRoot(ctx, rootFile, signer, newRoot, prev, exists, sealed); err != nil {
		return err
	}

	// The namespace no longer references the subtree; release its shards (best
	// effort — the pointer already advanced, so a failed delete only leaves
	// unreferenced ciphertext for the node's GC/lease expiry to reclaim).
	var deleted, missing, failed int
	for id := range shards {
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
	fmt.Printf("Removed rvk:%s (%d shard(s) released, %d already absent, %d failed)\n", target, deleted, missing, failed)
	return nil
}

// collectShards walks the DAG rooted at c and accumulates every shard content
// address it references into out: the blob's own shards, and — for a file
// manifest — its data-chunk shards, recursing through directory entries.
// Deduplication is inherent (the set keys on content address), so shards shared
// by identical blobs are released once.
func collectShards(ctx context.Context, s store.Store, c manifest.ReadCap, out map[store.ShardID]struct{}) error {
	for _, id := range c.Shards {
		out[id] = struct{}{}
	}
	switch c.Kind {
	case manifest.KindDir:
		d, err := manifest.LoadDir(ctx, s, c)
		if err != nil {
			return err
		}
		for _, e := range d.Entries {
			if err := collectShards(ctx, s, e.Cap, out); err != nil {
				return err
			}
		}
	case manifest.KindFile:
		fm, err := manifest.LoadFileManifest(ctx, s, c)
		if err != nil {
			return err
		}
		for _, ch := range fm.Chunks {
			for _, id := range ch.Shards {
				out[id] = struct{}{}
			}
		}
	}
	return nil
}

// --- share ----------------------------------------------------------------

// cmdShare seals a read-capability to the subtree at rvk:<path> for a recipient.
// It builds a RootPointer anchored at that subtree, signed by the caller so the
// recipient can verify authenticity, then wraps it to the recipient's ML-KEM-768
// public key so only they can open it (Architecture §3.5, §9.1: sharing = wrap
// to the recipient, never a bearer token). The recipient uses the resulting file
// as their -root, opening it with -key.
func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	node, bootstrap, mdns := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "namespace root file to share from (default $REVIKA_ROOT, else "+defaultRootPath+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root you are re-sharing from")
	signKeyPath := fs.String("signkey", defaultSignKeyPath, "your signing key, to sign the shared root")
	to := fs.String("to", "", "recipient public key (base64) or @file")
	out := fs.String("o", "", "output shared root file (default <name>.root.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || !isRvk(fs.Arg(0)) {
		return fmt.Errorf("share takes one rvk:<path>")
	}
	target := rvkPath(fs.Arg(0))
	recipient, err := resolveRecipient(*to)
	if err != nil {
		return err
	}
	signer, err := loadSignKey(*signKeyPath)
	if err != nil {
		return err
	}
	rootFile := rootPath(*rootFlag)
	prev, exists, _, err := loadRoot(rootFile, *keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to share", rootFile)
	}

	ctx := context.Background()
	s, closer, err := readBackend(ctx, *node, *bootstrap, *mdns)
	if err != nil {
		return err
	}
	defer closer()

	child, err := manifest.Resolve(ctx, s, prev.Root, target)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", target, err)
	}

	sharedRP, err := manifest.SignRoot(signer, child, 1, time.Now().UnixNano())
	if err != nil {
		return err
	}
	raw, err := provider.EncodeRootPointer(sharedRP)
	if err != nil {
		return err
	}
	sealed, err := cap.Wrap(recipient, raw)
	if err != nil {
		return err
	}

	outFile := *out
	if outFile == "" {
		base := path.Base(target)
		if base == "." || base == "/" || base == "" {
			base = "root"
		}
		outFile = base + ".root.json"
	}
	if err := os.WriteFile(outFile, sealed, 0o600); err != nil {
		return fmt.Errorf("write shared root: %w", err)
	}
	fmt.Printf("Sealed rvk:%s [%s] for recipient %s\n", target, child.Kind, recipient.String())
	fmt.Printf("Shared root: %s\n", outFile)
	fmt.Println("Send it to the recipient; they browse and retrieve it with:")
	fmt.Printf("  revika-ctl ls -node <ma> -root %s -key <their-privkey>\n", outFile)
	fmt.Printf("  revika-ctl cp -node <ma> -root %s -key <their-privkey> rvk:<path> <dst>\n", outFile)
	return nil
}

// --- node -----------------------------------------------------------------

// cmdNode lists the storage nodes the client can discover on the DHT — the nodes
// it is "aware of" and could place shards on. It joins the network via
// -bootstrap/-mdns, then reports each advertised node with its peer ID, whether
// we could reach it, and its advertised addresses.
func cmdNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
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

// readPrivateKey reads and parses an ML-KEM private key file (as written by
// keygen's <prefix>.key).
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
