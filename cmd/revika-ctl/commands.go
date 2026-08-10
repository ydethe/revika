package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/net"
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
	powFail := fs.Bool("pow-fail", false, "TESTING ONLY: mint a signing (owner) key that FAILS the pow check at -pow-difficulty, to exercise a node's pow-admission gate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *powDifficulty > 255 {
		return fmt.Errorf("pow-difficulty %d out of range (0-255)", *powDifficulty)
	}
	puzzle := cap.DefaultArgon2id()

	pub, err := mintAndWriteIdentity(*prefix, puzzle, cap.Difficulty(*powDifficulty), *powFail)
	if err != nil {
		return err
	}
	privPath := *prefix + ".key"
	pubPath := *prefix + ".pub"
	signPrivPath := *prefix + ".sign.key"
	signPubPath := *prefix + ".sign.pub"

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
func mintSigningKey(puzzle cap.Argon2idPuzzle, d cap.Difficulty) (cap.SignKey, cap.SignPubKey, error) {
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
func mintFailingSigningKey(puzzle cap.Argon2idPuzzle, d cap.Difficulty) (cap.SignKey, cap.SignPubKey, error) {
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

// mintAndWriteIdentity generates a User identity — an ML-KEM-768 encryption
// keypair for receiving shares and a proof-of-work-ground Ed25519 signing
// (owner) keypair — and writes all four files under prefix
// (<prefix>.key/.pub/.sign.key/.sign.pub), refusing to overwrite existing
// private keys. It returns the encryption public key for the caller to report.
// Shared by `keygen` and the on-demand identity creation a first write triggers
// inside a workspace (loadOrCreateSignKey).
func mintAndWriteIdentity(prefix string, puzzle cap.Argon2idPuzzle, d cap.Difficulty, powFail bool) (cap.PublicKey, error) {
	privPath := prefix + ".key"
	pubPath := prefix + ".pub"
	signPrivPath := prefix + ".sign.key"
	signPubPath := prefix + ".sign.pub"
	if _, err := os.Stat(privPath); err == nil {
		return cap.PublicKey{}, fmt.Errorf("refusing to overwrite existing private key %s", privPath)
	} else if !os.IsNotExist(err) {
		return cap.PublicKey{}, err
	}
	if _, err := os.Stat(signPrivPath); err == nil {
		return cap.PublicKey{}, fmt.Errorf("refusing to overwrite existing signing key %s", signPrivPath)
	} else if !os.IsNotExist(err) {
		return cap.PublicKey{}, err
	}

	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		return cap.PublicKey{}, err
	}
	mint := mintSigningKey
	if powFail {
		mint = mintFailingSigningKey
	}
	signKey, signPub, err := mint(puzzle, d)
	if err != nil {
		return cap.PublicKey{}, err
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return cap.PublicKey{}, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(privPath, []byte(priv.String()+"\n"), 0o600); err != nil {
		return cap.PublicKey{}, fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pub.String()+"\n"), 0o644); err != nil {
		return cap.PublicKey{}, fmt.Errorf("write public key: %w", err)
	}
	if err := os.WriteFile(signPrivPath, []byte(signKey.String()+"\n"), 0o600); err != nil {
		return cap.PublicKey{}, fmt.Errorf("write signing key: %w", err)
	}
	if err := os.WriteFile(signPubPath, []byte(signPub.String()+"\n"), 0o644); err != nil {
		return cap.PublicKey{}, fmt.Errorf("write signing public key: %w", err)
	}
	return pub, nil
}

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

// loadOrCreateSignKey returns the signing key at path. When it is missing, a
// write into a freshly `connect`ed workspace has no identity yet, so — if stdin
// is a terminal — it offers to mint one in place (both keypairs, at path's
// prefix), grinding proof-of-work to match the workspace's node policy. Declined
// or non-interactive, it errors rather than silently proceeding.
func loadOrCreateSignKey(w *Workspace, path string) (cap.SignKey, error) {
	if _, err := os.Stat(path); err == nil {
		return loadSignKey(path)
	} else if !os.IsNotExist(err) {
		return cap.SignKey{}, err
	}
	if !isTerminal(os.Stdin) {
		return cap.SignKey{}, fmt.Errorf("no signing identity at %s; run `revika-ctl keygen` first (or pass -signkey)", path)
	}
	puzzle, d, err := w.powSettings()
	if err != nil {
		return cap.SignKey{}, err
	}
	prefix := strings.TrimSuffix(path, ".sign.key")
	prompt := fmt.Sprintf("No revika identity found at %s.*\nCreate one now", prefix)
	if d > 0 {
		prompt += fmt.Sprintf(" (grinding %s proof-of-work at %d bits — may take a while)", puzzle.Name(), d)
	}
	prompt += "? [y/N] "
	ok, err := confirm(prompt)
	if err != nil {
		return cap.SignKey{}, err
	}
	if !ok {
		return cap.SignKey{}, fmt.Errorf("aborted: no identity created")
	}
	pub, err := mintAndWriteIdentity(prefix, puzzle, d, false)
	if err != nil {
		return cap.SignKey{}, err
	}
	fmt.Fprintf(os.Stderr, "Created identity at %s.* — encryption public key (share to receive files):\n%s\n", prefix, pub.String())
	return loadSignKey(path)
}

// confirm writes prompt to stderr and reads a yes/no answer from stdin,
// defaulting to no on a blank line or EOF.
func confirm(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// --- namespace addressing -------------------------------------------------

// rvkScheme prefixes an address that names the namespace rather than the local
// filesystem, e.g. rvk:docs/report.pdf.
const rvkScheme = "rvk:"

// isRvk reports whether s addresses the namespace (carries the rvk: scheme).
func isRvk(s string) bool { return strings.HasPrefix(s, rvkScheme) }

// rvkPath strips the rvk: scheme, returning the slash-separated namespace path
// (empty for the root itself).
func rvkPath(s string) string { return strings.TrimPrefix(s, rvkScheme) }

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

// commitConfig carries the inputs commitRoot needs beyond the pointer itself to
// run the multi-device read-merge-publish loop. The merge path activates only
// when every field it needs is present — a DHT backend that speaks the sealed
// self-root companion (pub is a fullRootPublisher) and the owner ML-KEM keys
// (mlkemOK). Absent either (a single -node store, a file-mode root, or missing
// keys) commit degrades to a plain local sign+save (+ best-effort DHT mirror),
// exactly as before multi-device support.
type commitConfig struct {
	file     string      // authoritative local root.json (also the merge base)
	signer   cap.SignKey // owner Ed25519
	mlkemOK  bool        // owner ML-KEM pair loaded (below)
	priv     cap.PrivateKey
	pub      cap.PublicKey
	label    manifest.MergeLabeler // conflict-copy namer (device-tagged)
	s        store.Store
	cfg      pipeline.Config
	// recipients is the authorized-device seal set for the self-root companion
	// (Architecture §3.7.2). Empty → legacy single-owner-key seal (SealFullRoot),
	// preserving pre-device-revocation behaviour for a workspace with no
	// devices.json. Non-empty → the companion is sealed per device (SealFullRootFor),
	// so a device dropped from the record can no longer open future roots. This
	// device's own ML-KEM key is always unioned in, so it never seals itself out.
	recipients []cap.PublicKey
}

// newCommitConfig assembles the commit inputs from a workspace: the owner
// ML-KEM keys (if present — absent disables merge) and the device-tagged
// conflict labeler. It never fails for a missing key file; only a malformed one
// is an error.
func (w *Workspace) newCommitConfig(rootFile string, signer cap.SignKey, s store.Store, cfg pipeline.Config) (commitConfig, error) {
	priv, pub, ok, err := w.ownerMLKEM()
	if err != nil {
		return commitConfig{}, err
	}
	recipients, err := w.companionRecipients(signer, pub, ok)
	if err != nil {
		return commitConfig{}, err
	}
	return commitConfig{
		file:       rootFile,
		signer:     signer,
		mlkemOK:    ok,
		priv:       priv,
		pub:        pub,
		label:      w.deviceLabeler(),
		s:          s,
		cfg:        cfg,
		recipients: recipients,
	}, nil
}

// companionRecipients returns the seal-recipient set for the self-root companion:
// every device in this workspace's device-authorization record (devices.json),
// unioned with this device's own ML-KEM key so a commit never seals itself out.
// It returns nil (→ legacy single-owner seal) when there is no record, the record
// is empty, or the owner ML-KEM key is absent. A record whose owner does not match
// the signer is ignored (it governs a different namespace).
func (w *Workspace) companionRecipients(signer cap.SignKey, selfPub cap.PublicKey, mlkemOK bool) ([]cap.PublicKey, error) {
	if !mlkemOK {
		return nil, nil
	}
	auth, ok, err := w.loadDeviceAuth()
	if err != nil {
		return nil, err
	}
	if !ok || len(auth.Members) == 0 || auth.Owner != signer.Public() {
		return nil, nil
	}
	recipients := auth.Recipients()
	// Union in this device's own key (idempotent if already a member).
	if !slices.Contains(recipients, selfPub) {
		recipients = append(recipients, selfPub)
	}
	return recipients, nil
}

// fullRootPublisher is the DHT surface commitRoot needs for multi-device merge:
// the plain RootPublisher (verify-root) plus the sealed self-root companion that
// delivers a decryptable remote root to the owner's other devices.
// *net.Discovery satisfies it structurally.
type fullRootPublisher interface {
	provider.RootPublisher
	PutFullRoot(ctx context.Context, r manifest.FullRootRecord) error
	GetFullRoot(ctx context.Context, owner cap.SignPubKey, priv cap.PrivateKey, pub cap.PublicKey, verifyRoot manifest.ReadCap) (manifest.ReadCap, bool, error)
}

// commitMaxAttempts bounds the read-merge-publish retry loop. A DHT has no CAS,
// so each attempt narrows but cannot close the publish race; after this many
// concurrent-writer collisions the commit stays durable locally (root.json) and
// its changes fold in on the next write.
const commitMaxAttempts = 5

// commitRoot advances the namespace to newRoot, reconciling with any concurrent
// write another of the User's devices published under the shared owner key. It
// refuses to modify a sealed (shared) or foreign-owned root.
//
// With a DHT backend and the owner ML-KEM keys it runs a read-merge-publish
// loop: read the current DHT root (and, on a fork, its decryptable companion),
// three-way merge divergent trees via manifest.Merge3 (conflicting leaves become
// device-tagged conflict copies, never silent losses), sign at a monotonically
// higher Seq, publish companion then verify-root, and re-read to catch a racing
// writer — folding and retrying if one won. The durable local root.json stays
// authoritative (a DHT failure never fails the commit). Absent the DHT or the
// keys it degrades to commitLocalOnly.
func commitRoot(ctx context.Context, cc commitConfig, newRoot manifest.ReadCap, prev manifest.RootPointer, exists, sealed bool, pub provider.RootPublisher) error {
	if sealed {
		return fmt.Errorf("root %s is a shared, read-only root (sealed to you); it cannot be modified", cc.file)
	}
	if exists && prev.Owner != cc.signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", cc.file)
	}

	frp, canMerge := pub.(fullRootPublisher)
	if !canMerge || !cc.mlkemOK {
		// No decryptable-remote channel: single-writer or degraded. Publish as before.
		return commitLocalOnly(ctx, cc, newRoot, prev, exists, pub)
	}
	owner := cc.signer.Public()

	localTip := newRoot
	prevSeq := uint64(0)
	if exists {
		prevSeq = prev.Seq
	}

	for attempt := 0; attempt < commitMaxAttempts; attempt++ {
		remote, hasRemote, err := pub.GetRoot(ctx, owner)
		if err != nil {
			// DHT resolution failed this round; fall back to a durable local commit
			// (with best-effort mirror) so the write is not lost to a transient miss.
			ctlLog.Warn("commit: dht root read failed, committing locally", "event", "root.commit", "err", err)
			return commitLocalOnly(ctx, cc, localTip, prev, exists, pub)
		}
		// The merge base is this device's last committed root — prev, the durable
		// root.json loaded above. root.json and its (former) base sidecar were always
		// written together with the same cap+seq, so prev.Root/prev.Seq are exactly
		// that ancestor; it stays constant across retries while localTip/prevSeq advance.
		newSeq := prevSeq + 1
		if hasRemote && remote.Seq+1 > newSeq {
			newSeq = remote.Seq + 1
		}

		merged := localTip
		var conflicts []string
		switch {
		case !hasRemote:
			// Nothing published yet.
		case exists && remote.Seq < prev.Seq:
			// We are strictly ahead of the published root; it is our own ancestor.
		case exists && sameVerify(remote.Root, prev.Root):
			// The published root is exactly our merge base: a pure local advance.
		default:
			// Fork (or unknown ancestor): fetch the decryptable remote root and merge.
			remoteFull, ok, ferr := frp.GetFullRoot(ctx, owner, cc.priv, cc.pub, remote.Root)
			if ferr != nil || !ok {
				// Cannot decrypt the remote (companion missing/stale/mismatched). Do
				// not silently overwrite it: keep our advance durable locally and
				// surface it; the other device's next reconcile still sees our root.
				ctlLog.Warn("commit: remote root present but its companion could not be opened; publishing our root without merge",
					"event", "root.commit", "remote_seq", remote.Seq, "err", ferr)
			} else {
				baseCap := manifest.ReadCap{}
				if exists {
					baseCap = prev.Root
				}
				m, cf, merr := manifest.Merge3(ctx, cc.s, cc.cfg, baseCap, localTip, remoteFull, cc.label)
				if merr != nil {
					return fmt.Errorf("merge divergent roots: %w", merr)
				}
				merged, conflicts = m, cf
			}
		}

		rp, err := manifest.SignRoot(cc.signer, merged, newSeq, time.Now().UnixNano())
		if err != nil {
			return err
		}
		rec, err := cc.sealCompanion(merged, newSeq)
		if err != nil {
			return err
		}
		// Publish the companion first (so a reader that sees the verify-root can
		// open it), then the verify-root. Both best-effort: the local save below is
		// authoritative and a mirror failure must not fail the commit.
		if err := frp.PutFullRoot(ctx, rec); err != nil {
			ctlLog.Warn("commit: publish self-root companion failed", "event", "root.commit", "seq", newSeq, "err", err)
		}
		if err := pub.PutRoot(ctx, rp); err != nil {
			ctlLog.Warn("commit: publish verify-root failed", "event", "root.commit", "seq", newSeq, "err", err)
		}

		// Re-read to catch a writer that raced us to this Seq. If someone else's
		// record won (equal-or-higher Seq, different root), fold our merge in and
		// retry at a higher Seq so no side's changes are dropped.
		if cur, ok, rerr := pub.GetRoot(ctx, owner); rerr == nil && ok && cur.Seq >= newSeq && !sameVerify(cur.Root, merged) {
			localTip = merged
			prevSeq = cur.Seq
			continue
		}

		if err := provider.NewFileRootStore(cc.file).Save(ctx, rp); err != nil {
			return err
		}
		reportConflicts(conflicts)
		return nil
	}
	// Exhausted retries against a hot race; the local root file still holds our
	// last signed attempt and its changes fold in on the next write.
	return fmt.Errorf("commit: gave up after %d attempts racing a concurrent writer (change kept locally, will reconcile on next write)", commitMaxAttempts)
}

// sealCompanion builds the self-root companion for a commit: a device-scoped
// record sealed to every authorized device when this workspace has a
// device-authorization record (cc.recipients non-empty, Architecture §3.7.2),
// else the legacy single-owner-key record. Both are opened by GetFullRoot the
// same way, so the choice is transparent to readers.
func (cc commitConfig) sealCompanion(root manifest.ReadCap, seq uint64) (manifest.FullRootRecord, error) {
	if len(cc.recipients) > 0 {
		return manifest.SealFullRootFor(cc.signer, cc.recipients, root, seq)
	}
	return manifest.SealFullRoot(cc.signer, cc.pub, root, seq)
}

// commitLocalOnly is the pre-multi-device commit: sign at prev.Seq+1 (1 for a
// fresh namespace) and save to the durable local file, mirroring to the DHT
// verify-root best-effort when a publisher is available. The saved root.json is
// itself the merge base a later multi-device-capable commit reads as its ancestor.
func commitLocalOnly(ctx context.Context, cc commitConfig, newRoot manifest.ReadCap, prev manifest.RootPointer, exists bool, pub provider.RootPublisher) error {
	seq := uint64(1)
	if exists {
		seq = prev.Seq + 1
	}
	rp, err := manifest.SignRoot(cc.signer, newRoot, seq, time.Now().UnixNano())
	if err != nil {
		return err
	}
	var rs provider.RootStore = provider.NewFileRootStore(cc.file)
	if pub != nil {
		rs = provider.NewMultiRootStore(ctlLog, rs, provider.NewDHTRootStore(pub, cc.signer.Public()))
	}
	return rs.Save(ctx, rp)
}

// sameVerify reports whether two caps address the identical blob ignoring their
// AES key — comparing verify projections. It bridges the key-stripped DHT root
// (remote.Root) and the key-bearing local caps (base, merged) when detecting a
// fork or a race.
func sameVerify(a, b manifest.ReadCap) bool {
	ab, err := a.VerifyCap().ReadCap().MarshalBinary()
	if err != nil {
		return false
	}
	bb, err := b.VerifyCap().ReadCap().MarshalBinary()
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// reportConflicts prints the paths a merge filed as conflict copies, so a User
// sees a genuine divergence rather than it passing silently.
func reportConflicts(conflicts []string) {
	for _, p := range conflicts {
		fmt.Printf("conflict: rvk:%s diverged across devices; kept both (see the conflict copy)\n", p)
	}
}

// rootPublisher recovers the DHT root publisher from a write/read store, or nil
// when the backend is not DHT-backed (a single -node store, which cannot publish
// a root). A PlacementStore and a DHTStore both embed the DHT layer and expose it
// via Discovery(); *net.Discovery satisfies provider.RootPublisher (and
// fullRootPublisher) structurally.
func rootPublisher(s store.Store) provider.RootPublisher {
	if d, ok := s.(interface{ Discovery() *net.Discovery }); ok {
		return d.Discovery()
	}
	return nil
}

// --- backends -------------------------------------------------------------

// addBackendFlags registers the shared node-selection flag on fs. The DHT
// bootstrap peers come from the workspace (-root); -node overrides it, pinning a
// single node.
func addBackendFlags(fs *flag.FlagSet) (node *string) {
	node = fs.String("node", "", "use this single node multiaddr (with /p2p/<peerid>); overrides the workspace's bootstrap peers")
	return
}

// readBackend selects a read store: a single node (-node) or a DHT-backed store
// that discovers each shard's providers via the workspace's bootstrap peers.
func readBackend(ctx context.Context, node string, bootstrap []string) (store.Store, func(), error) {
	switch {
	case node != "":
		return dial(ctx, node)
	case len(bootstrap) > 0:
		return dialDHT(ctx, bootstrap)
	default:
		return nil, nil, fmt.Errorf("no backend: pass -node <ma>, or select a workspace with saved bootstrap peers via -root")
	}
}

// writeBackend selects a read+write store the namespace is mutated through. With
// -node it targets that single node (a NetStore does Get/Put/Delete); otherwise
// it joins the DHT and returns a PlacementStore, which spreads new shards across
// discovered nodes while still reading directory blobs back via the DHT.
func writeBackend(ctx context.Context, node string, bootstrap []string, signer cap.SignKey, grantExpiry int64, cfg pipeline.Config) (store.Store, func(), error) {
	switch {
	case node != "":
		return dialSigned(ctx, node, signer)
	case len(bootstrap) > 0:
		ps, closer, err := dialPlacement(ctx, bootstrap, signer)
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
		return nil, nil, fmt.Errorf("no backend: pass -node <ma>, or select a workspace with saved bootstrap peers via -root")
	}
}

// --- cp -------------------------------------------------------------------

// cmdCp copies between the local filesystem and the namespace, scp-style, or
// within the namespace when both endpoints carry the rvk: prefix. Storing grafts
// the local file or subtree into the -root and advances its signed sequence;
// retrieving resolves the rvk: path and reconstructs it locally; an rvk:→rvk:
// copy is a pure copy-on-write graft of the source cap at the destination (no
// re-encryption, shards shared by content address).
func cmdCp(args []string) error {
	fs := flag.NewFlagSet("cp", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder or root file (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root")
	signKeyFlag := fs.String("signkey", "", "your signing key, authorizing writes (default <workspace>/keys/user.sign.key)")
	grantTTL := fs.Duration("grant-ttl", 0, "expiry of the repair grants attached to stored shards (0 = never)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("cp takes <src> <dst>; exactly one carries the rvk: prefix")
	}
	src, dst := fs.Arg(0), fs.Arg(1)
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	ctx := context.Background()

	switch {
	case isRvk(dst) && !isRvk(src):
		return cpStore(ctx, ws, src, rvkPath(dst), *keyPath, *signKeyFlag, *node, *grantTTL)
	case isRvk(src) && !isRvk(dst):
		return cpRetrieve(ctx, ws, rvkPath(src), dst, *keyPath, *node)
	case isRvk(src) && isRvk(dst):
		return cpCopy(ctx, ws, rvkPath(src), rvkPath(dst), *keyPath, *signKeyFlag, *node)
	default:
		return fmt.Errorf("cp needs exactly one rvk: path, e.g. `cp file rvk:dir/` (store) or `cp rvk:dir/file .` (retrieve)")
	}
}

// cpStore stores the local src (a file, symlink, or directory) into the
// namespace at dstRvk, grafting it into the -root and committing an advanced
// RootPointer.
func cpStore(ctx context.Context, ws *Workspace, src, dstRvk, keyPath, signKeyFlag, node string, grantTTL time.Duration) error {
	rootFile := ws.RootFile
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(signKeyFlag))
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

	cfg := ws.pipelineConfig()
	var grantExpiry int64
	if grantTTL > 0 {
		grantExpiry = time.Now().Add(grantTTL).Unix()
	}
	node, bootstrap := ws.backend(node)
	s, closer, err := writeBackend(ctx, node, bootstrap, signer, grantExpiry, cfg)
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
		size  int64
	)
	start := time.Now()
	if fi.IsDir() {
		c, _, serr := storeTree(ctx, s, cfg, src)
		if serr != nil {
			return fmt.Errorf("store %s: %w", src, serr)
		}
		child = c
		stat = manifest.StatCache{Kind: manifest.KindDir, Mode: uint32(fi.Mode())}
		label = "directory " + src
		size = treeBytes(src)
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
		size = int64(fm.Size)
	}
	elapsed := time.Since(start)

	dstPath := destPath(ctx, s, root, dstRvk, filepath.Base(src))
	newRoot, err := manifest.Graft(ctx, s, cfg, root, dstPath, child, stat)
	if err != nil {
		return fmt.Errorf("graft rvk:%s: %w", dstPath, err)
	}
	cc, err := ws.newCommitConfig(rootFile, signer, s, cfg)
	if err != nil {
		return err
	}
	if err := commitRoot(ctx, cc, newRoot, prev, exists, sealed, rootPublisher(s)); err != nil {
		return err
	}
	fmt.Printf("Stored %s -> rvk:%s\n", label, dstPath)
	if secs := elapsed.Seconds(); secs > 0 {
		throughputMBps := (float64(size) / (1024 * 1024)) / secs
		fmt.Printf("Transferred to revika in %s (~%.2f MB/s)\n", elapsed.Round(time.Millisecond), throughputMBps)
	} else {
		fmt.Printf("Transferred to revika in %s\n", elapsed.Round(time.Millisecond))
	}
	return nil
}

// treeBytes sums the sizes of the regular files under src for a throughput
// estimate. It stats only; unreadable entries are skipped so a best-effort
// figure is always available.
func treeBytes(src string) int64 {
	var total int64
	filepath.WalkDir(src, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total
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
func cpRetrieve(ctx context.Context, ws *Workspace, srcRvk, dst, keyPath, node string) error {
	rootFile := ws.RootFile
	prev, exists, _, err := loadRoot(rootFile, keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to retrieve", rootFile)
	}
	node, bootstrap := ws.backend(node)
	s, closer, err := readBackend(ctx, node, bootstrap)
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

// cpCopy copies a file or subtree from one rvk: path to another within the same
// namespace root. It is a metadata-only operation: because every blob is
// immutable and content-addressed, the copy grafts the source's existing cap at
// the destination (copy-on-write up the destination path), so the two paths
// share the same shards — no re-encryption and no shard movement. The source
// cap's StatCache is preserved so the copy keeps its size/mode/mtime. The
// destination follows cp/scp semantics via destPath (trailing slash or an
// existing directory means "into it under the source's base name").
//
// Because the copy shares shards with the source, rm/revoke reclaim a shard only
// once nothing under the current root still references it (see cmdRm's keep-set).
func cpCopy(ctx context.Context, ws *Workspace, srcRvk, dstRvk, keyPath, signKeyFlag, node string) error {
	rootFile := ws.RootFile
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(signKeyFlag))
	if err != nil {
		return err
	}
	prev, exists, sealed, err := loadRoot(rootFile, keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to copy", rootFile)
	}
	if sealed {
		return fmt.Errorf("cannot copy within a shared, read-only root (%s)", rootFile)
	}
	if prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", rootFile)
	}

	cfg := ws.pipelineConfig()
	node, bootstrap := ws.backend(node)
	s, closer, err := writeBackend(ctx, node, bootstrap, signer, 0, cfg)
	if err != nil {
		return err
	}
	defer closer()

	srcEntry, err := manifest.ResolveEntry(ctx, s, prev.Root, srcRvk)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", srcRvk, err)
	}
	base := path.Base(srcRvk)
	if base == "." || base == "/" || base == "" {
		return fmt.Errorf("cannot copy the namespace root itself; name a specific rvk: source")
	}
	dstPath := destPath(ctx, s, prev.Root, dstRvk, base)

	newRoot, err := manifest.Graft(ctx, s, cfg, prev.Root, dstPath, srcEntry.Cap, srcEntry.Stat)
	if err != nil {
		return fmt.Errorf("graft rvk:%s: %w", dstPath, err)
	}
	cc, err := ws.newCommitConfig(rootFile, signer, s, cfg)
	if err != nil {
		return err
	}
	if err := commitRoot(ctx, cc, newRoot, prev, exists, sealed, rootPublisher(s)); err != nil {
		return err
	}
	fmt.Printf("Copied rvk:%s -> rvk:%s [%s]\n", srcRvk, dstPath, srcEntry.Cap.Kind)
	return nil
}

// --- mv -------------------------------------------------------------------

// cmdMv renames or moves a file or subtree within the namespace from one rvk:
// path to another. Both endpoints must carry the rvk: prefix (mv is
// namespace-internal — use cp to cross the local filesystem boundary).
func cmdMv(args []string) error {
	fs := flag.NewFlagSet("mv", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder or root file (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root")
	signKeyFlag := fs.String("signkey", "", "your signing key, authorizing the move (default <workspace>/keys/user.sign.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || !isRvk(fs.Arg(0)) || !isRvk(fs.Arg(1)) {
		return fmt.Errorf("mv takes rvk:<src> rvk:<dst> (both name the namespace; use cp to cross to/from local files)")
	}
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	return mvRename(context.Background(), ws, rvkPath(fs.Arg(0)), rvkPath(fs.Arg(1)), *keyPath, *signKeyFlag, *node)
}

// mvRename moves srcRvk to dstRvk within the same namespace root. Like cpCopy it
// is a metadata-only copy-on-write operation — it grafts the source's existing
// cap at the destination and removes the source entry, committing a single
// advanced RootPointer — so no bytes are re-encrypted or moved: the shards stay
// put (referenced by content address at the new path) and only their name
// changes. The destination follows cp/scp semantics via destPath (a trailing
// slash or an existing directory means "into it under the source's base name").
func mvRename(ctx context.Context, ws *Workspace, srcRvk, dstRvk, keyPath, signKeyFlag, node string) error {
	rootFile := ws.RootFile
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(signKeyFlag))
	if err != nil {
		return err
	}
	prev, exists, sealed, err := loadRoot(rootFile, keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to move", rootFile)
	}
	if sealed {
		return fmt.Errorf("cannot move within a shared, read-only root (%s)", rootFile)
	}
	if prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", rootFile)
	}

	cfg := ws.pipelineConfig()
	node, bootstrap := ws.backend(node)
	s, closer, err := writeBackend(ctx, node, bootstrap, signer, 0, cfg)
	if err != nil {
		return err
	}
	defer closer()

	srcEntry, err := manifest.ResolveEntry(ctx, s, prev.Root, srcRvk)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", srcRvk, err)
	}
	base := path.Base(srcRvk)
	if base == "." || base == "/" || base == "" {
		return fmt.Errorf("cannot move the namespace root itself; name a specific rvk: source")
	}
	dstPath := destPath(ctx, s, prev.Root, dstRvk, base)

	// Reject a no-op and a move of a subtree into itself or one of its descendants:
	// both would graft the entry and then remove it (or its new home) in the same
	// commit, silently dropping the data.
	srcClean, dstClean := path.Clean(srcRvk), path.Clean(dstPath)
	if srcClean == dstClean {
		return fmt.Errorf("source and destination are the same path (rvk:%s)", srcClean)
	}
	if strings.HasPrefix(dstClean+"/", srcClean+"/") {
		return fmt.Errorf("cannot move rvk:%s into its own subtree (rvk:%s)", srcClean, dstClean)
	}

	// Graft the source cap at the destination, then remove the source — a single
	// new root, so the move is atomic (never a window with two copies or none).
	moved, err := manifest.Graft(ctx, s, cfg, prev.Root, dstPath, srcEntry.Cap, srcEntry.Stat)
	if err != nil {
		return fmt.Errorf("graft rvk:%s: %w", dstPath, err)
	}
	newRoot, err := manifest.GraftRemove(ctx, s, cfg, moved, srcRvk)
	if err != nil {
		return fmt.Errorf("remove source rvk:%s: %w", srcRvk, err)
	}
	cc, err := ws.newCommitConfig(rootFile, signer, s, cfg)
	if err != nil {
		return err
	}
	if err := commitRoot(ctx, cc, newRoot, prev, exists, sealed, rootPublisher(s)); err != nil {
		return err
	}
	fmt.Printf("Moved rvk:%s -> rvk:%s [%s]\n", srcRvk, dstPath, srcEntry.Cap.Kind)
	return nil
}

// --- ls -------------------------------------------------------------------

// cmdLs lists a directory in the namespace, reading directory blobs only (no
// file content). Plain output is one name per line (directories end in /); -l
// adds kind/size/mtime and -R recurses.
func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder or root file (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root")
	owner := fs.String("owner", "", "file holding an owner's signing pubkey (base64); resolves their published root from the DHT and reports the verify-only pointer, does not decrypt")
	long := fs.Bool("l", false, "long format: kind, size, and mtime per entry")
	recurse := fs.Bool("R", false, "list subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *owner != "" {
		return lsPublishedRoot(*rootFlag, *node, *owner)
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

	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	rootFile := ws.RootFile
	prev, exists, _, err := loadRoot(rootFile, *keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to list", rootFile)
	}

	ctx := context.Background()
	eNode, eBootstrap := ws.backend(*node)
	s, closer, err := readBackend(ctx, eNode, eBootstrap)
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

// lsPublishedRoot resolves ownerB64's current signed RootPointer from the DHT and
// prints its summary. The DHT record is a *verify* projection — it carries no
// decryption key — so this reports liveness and the anchor (seq + verify cap)
// rather than descending into the (encrypted) directory: it answers "is this
// identity's namespace published, at what sequence, over which shards" and lets a
// share recipient detect revocation (their old shard IDs vanish from the current
// root after the owner runs `revoke`). Actually reading the content still needs
// the read key, delivered out-of-band as a sealed share (-key).
func lsPublishedRoot(rootFlag, node, ownerFile string) error {
	raw, err := os.ReadFile(ownerFile)
	if err != nil {
		return fmt.Errorf("read -owner key file: %w", err)
	}
	owner, err := cap.ParseSignPubKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("parse -owner key file %s: %w", ownerFile, err)
	}
	ws, err := resolveWorkspace(rootFlag)
	if err != nil {
		return err
	}
	eNode, eBootstrap := ws.backend(node)
	ctx := context.Background()
	s, closer, err := readBackend(ctx, eNode, eBootstrap)
	if err != nil {
		return err
	}
	defer closer()

	pub := rootPublisher(s)
	if pub == nil {
		return fmt.Errorf("-owner needs a DHT backend (a workspace with bootstrap peers); a single -node cannot resolve a published root")
	}
	rp, ok, err := pub.GetRoot(ctx, owner)
	if err != nil {
		return fmt.Errorf("resolve published root for %s: %w", owner, err)
	}
	if !ok {
		return fmt.Errorf("no published root for owner %s", owner)
	}
	fmt.Printf("Published root for %s\n", owner)
	fmt.Printf("  seq:    %d\n", rp.Seq)
	fmt.Printf("  time:   %s\n", time.Unix(0, rp.TimeNS).Format(time.RFC3339))
	fmt.Printf("  kind:   %s\n", rp.Root.Kind)
	fmt.Printf("  shards: %d (verify-only; k=%d m=%d)\n", len(rp.Root.Shards), rp.Root.K, rp.Root.M)
	fmt.Println("  (verify-only pointer — decrypting the namespace needs the read key from a sealed share)")
	return nil
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
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder or root file (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	signKeyFlag := fs.String("signkey", "", "your signing key, authorizing the delete (default <workspace>/keys/user.sign.key)")
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

	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	rootFile := ws.RootFile
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(*signKeyFlag))
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
	cfg := ws.pipelineConfig()
	eNode, eBootstrap := ws.backend(*node)
	s, closer, err := writeBackend(ctx, eNode, eBootstrap, signer, 0, cfg)
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
	cc, err := ws.newCommitConfig(rootFile, signer, s, cfg)
	if err != nil {
		return err
	}
	if err := commitRoot(ctx, cc, newRoot, prev, exists, sealed, rootPublisher(s)); err != nil {
		return err
	}

	// The namespace no longer references the subtree; release its shards (best
	// effort — the pointer already advanced, so a failed delete only leaves
	// unreferenced ciphertext for the node's GC/lease expiry to reclaim). Only
	// drop shards nothing under the new root still references: an rvk:→rvk: copy
	// (cpCopy) grafts the same cap at two paths, so its shards are shared by
	// content address and must survive removing one path. Diffing against
	// everything reachable from the new root also spares shards a sibling shares.
	keep := map[store.ShardID]struct{}{}
	if err := collectShards(ctx, s, newRoot, keep); err != nil {
		return fmt.Errorf("enumerate remaining namespace shards: %w", err)
	}
	var deleted, missing, failed, kept int
	for id := range shards {
		if _, ok := keep[id]; ok {
			kept++
			continue
		}
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
	fmt.Printf("Removed rvk:%s (%d shard(s) released, %d already absent, %d still referenced, %d failed)\n", target, deleted, missing, kept, failed)
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

// --- revoke ---------------------------------------------------------------

// cmdRevoke rotates the read-capabilities of a subtree so a previously-shared
// cap can no longer read the current bytes (Architecture §3.5). It re-encrypts
// every blob at and below rvk:<path> down to the data chunks under fresh keys
// (manifest.Rekey), grafts the freshly-encrypted subtree into a new root, commits
// the advanced (and republished) RootPointer, then reclaims the orphaned old
// shards. A holder of the old cap keeps only ciphertext that is being garbage
// collected; they cannot follow the namespace forward.
//
// Honest limit: revocation denies *future* reads. Anyone who already downloaded
// the old shards and holds the old key keeps that stale copy — keys cannot be
// clawed back, only the data they open can be rotated out from under them.
func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder or root file (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	signKeyFlag := fs.String("signkey", "", "your signing key, authorizing the rekey (default <workspace>/keys/user.sign.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || !isRvk(fs.Arg(0)) {
		return fmt.Errorf("revoke takes one rvk:<path> (rvk: alone rekeys the whole namespace)")
	}
	target := rvkPath(fs.Arg(0))

	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	rootFile := ws.RootFile
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(*signKeyFlag))
	if err != nil {
		return err
	}
	prev, exists, sealed, err := loadRoot(rootFile, "")
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to revoke", rootFile)
	}
	if sealed {
		return fmt.Errorf("cannot revoke on a shared, read-only root (%s)", rootFile)
	}
	if prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; your signing key cannot modify it", rootFile)
	}

	ctx := context.Background()
	cfg := ws.pipelineConfig()
	eNode, eBootstrap := ws.backend(*node)
	s, closer, err := writeBackend(ctx, eNode, eBootstrap, signer, 0, cfg)
	if err != nil {
		return err
	}
	defer closer()

	// Snapshot the old subtree's shards before rekeying, so we can reclaim exactly
	// the ones the rotation orphans.
	oldSub, err := manifest.Resolve(ctx, s, prev.Root, target)
	if err != nil {
		return fmt.Errorf("resolve rvk:%s: %w", target, err)
	}
	oldShards := map[store.ShardID]struct{}{}
	if err := collectShards(ctx, s, oldSub, oldShards); err != nil {
		return fmt.Errorf("enumerate shards of rvk:%s: %w", target, err)
	}

	newRoot, err := manifest.Rekey(ctx, s, cfg, prev.Root, target)
	if err != nil {
		return fmt.Errorf("rekey rvk:%s: %w", target, err)
	}
	cc, err := ws.newCommitConfig(rootFile, signer, s, cfg)
	if err != nil {
		return err
	}
	if err := commitRoot(ctx, cc, newRoot, prev, exists, sealed, rootPublisher(s)); err != nil {
		return err
	}

	// Reclaim only shards the new namespace no longer references. Diffing against
	// everything reachable from the new root (not just the new subtree) keeps any
	// shard a sibling still shares by content address (best effort — the pointer
	// already advanced, so a failed delete only leaves unreferenced ciphertext for
	// the node's GC to reclaim).
	keep := map[store.ShardID]struct{}{}
	if err := collectShards(ctx, s, newRoot, keep); err != nil {
		return fmt.Errorf("enumerate new namespace shards: %w", err)
	}
	var deleted, missing, failed, kept int
	for id := range oldShards {
		if _, ok := keep[id]; ok {
			kept++
			continue
		}
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
	fmt.Printf("Revoked rvk:%s — rotated caps under a fresh key, advanced root to seq %d\n", target, prev.Seq+1)
	fmt.Printf("Reclaimed %d orphaned shard(s) (%d already absent, %d still shared, %d failed)\n", deleted, missing, kept, failed)
	fmt.Println("Note: previously-shared caps can no longer read the current data; already-downloaded copies cannot be recalled.")
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
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder or root file to share from (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	keyPath := fs.String("key", "", "private key to open a sealed shared root you are re-sharing from")
	signKeyFlag := fs.String("signkey", "", "your signing key, to sign the shared root (default <workspace>/keys/user.sign.key)")
	to := fs.String("to", "", "file holding the recipient's public key (base64, as written by keygen's .pub)")
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
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(*signKeyFlag))
	if err != nil {
		return err
	}
	rootFile := ws.RootFile
	prev, exists, _, err := loadRoot(rootFile, *keyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("namespace root %s does not exist; nothing to share", rootFile)
	}

	ctx := context.Background()
	eNode, eBootstrap := ws.backend(*node)
	s, closer, err := readBackend(ctx, eNode, eBootstrap)
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
// it is "aware of" and could place shards on. It joins the network through the
// workspace's saved bootstrap peers (-root), then reports each advertised node
// with its peer ID, whether we could reach it, and its advertised addresses.
// cmdNodeKey mints a fresh libp2p node identity key file and prints its Peer ID.
// It exists so a bootstrap/seed identity for local docker-compose or CI runs is
// generated on demand and git-ignored, never committed to the repository (issue
// #13). The Peer ID is the sole stdout line so a shell can capture it:
//
//	peerid=$(revika-ctl nodekey -o deploy/seed.key)
func cmdNodeKey(args []string) error {
	fs := flag.NewFlagSet("nodekey", flag.ExitOnError)
	out := fs.String("o", "", "path to write the new libp2p node identity key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("nodekey: -o <path> is required")
	}
	id, err := net.GenerateIdentityFile(*out)
	if err != nil {
		return err
	}
	// Diagnostics go to stderr (ctlLog); the Peer ID alone goes to stdout so it is
	// safe to capture in `$(...)` without the log line leaking into the value.
	ctlLog.Info("generated node identity", "path", *out, "peer_id", id.String())
	fmt.Println(id.String())
	return nil
}

func cmdNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	rootFlag := fs.String("root", "", "workspace folder supplying the bootstrap peers (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	_, bootstrap := ws.backend("")

	ctx := context.Background()
	h, disc, closer, err := joinDHT(ctx, bootstrap)
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
