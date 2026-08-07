package main

// device.go implements `revika-ctl device` — the User-side machinery for the
// *master credential* and the devices it authorizes (Architecture §3.7.2).
//
// The User is a principal, not a single keyholder. The master credential is the
// owner Ed25519 signing key (kept offline; the same key that already signs roots),
// the sole authority allowed to change the device set. Each device is one ML-KEM
// keypair — the workspace's user.key/.pub — authorized to open the sealed self-root
// companion. Authorization lives in a signed device-authorization record
// (device.Auth) persisted at <workspace>/devices.json and mirrored to the DHT.
//
// Read revocation rides on the companion: it is sealed once per authorized device
// (manifest.SealFullRootFor), so dropping a device from the record and resealing to
// the survivors — which enroll/revoke do by advancing and re-committing the root —
// means the revoked device's key no longer opens the current root. Like every
// revika revocation this is forward-only: a revoked device keeps whatever plaintext
// it already downloaded; the record only governs future bytes.
//
// Subcommands:
//
//	device id                          print this device's ID and ML-KEM public key
//	device init   [-label <s>]         bootstrap the record with this device as the first member
//	device enroll <pubkey-file> [-label <s>]   authorize another device's ML-KEM public key
//	device revoke <device-id>          de-authorize a device (reseals to the survivors)
//	device list                        list the currently authorized devices

import (
	"context"
	"flag"
	"fmt"
	"os"

	"revika/internal/cap"
	"revika/internal/device"
)

// deviceAuthPublisher is the DHT surface used to mirror the device-authorization
// record. *net.Discovery satisfies it structurally; recovered from a write store
// via rootPublisher.
type deviceAuthPublisher interface {
	PutDeviceAuth(ctx context.Context, a device.Auth) error
}

// cmdDevice dispatches the device subcommands.
func cmdDevice(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("device needs a subcommand: id | init | enroll | revoke | list")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "id":
		return cmdDeviceID(rest)
	case "init":
		return cmdDeviceInit(rest)
	case "enroll":
		return cmdDeviceEnroll(rest)
	case "revoke":
		return cmdDeviceRevoke(rest)
	case "list", "ls":
		return cmdDeviceList(rest)
	default:
		return fmt.Errorf("device: unknown subcommand %q (want id | init | enroll | revoke | list)", sub)
	}
}

// thisDevicePub returns this workspace's own ML-KEM public key — its device
// identity in the record. It errors when the key is absent, since every device
// subcommand needs to know who "this device" is.
func thisDevicePub(w *Workspace) (cap.PublicKey, error) {
	_, pub, ok, err := w.ownerMLKEM()
	if err != nil {
		return cap.PublicKey{}, err
	}
	if !ok {
		return cap.PublicKey{}, fmt.Errorf("this workspace has no ML-KEM key (%s.key); run `revika-ctl keygen` or `connect` first", w.keyPrefix())
	}
	return pub, nil
}

// cmdDeviceID prints this device's derived ID and ML-KEM public key, noting
// whether the local record already authorizes it.
func cmdDeviceID(args []string) error {
	fs := flag.NewFlagSet("device id", flag.ExitOnError)
	rootFlag := fs.String("root", "", "workspace folder (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	pub, err := thisDevicePub(ws)
	if err != nil {
		return err
	}
	id := device.NewID(pub)
	fmt.Printf("device id:  %s\n", id)
	fmt.Printf("public key: %s\n", pub.String())

	auth, ok, err := ws.loadDeviceAuth()
	if err != nil {
		return err
	}
	switch {
	case !ok:
		fmt.Println("record:     none yet (legacy single-owner mode; run `device init`)")
	case auth.Authorized(id):
		fmt.Printf("record:     authorized (seq %d, %d device(s))\n", auth.Seq, len(auth.Members))
	default:
		fmt.Printf("record:     NOT authorized (seq %d) — this device cannot open the current root\n", auth.Seq)
	}
	return nil
}

// cmdDeviceInit bootstraps the device-authorization record with this device as the
// first member, signed by the master (owner) credential. It refuses to clobber an
// existing record. The record is authoritative locally; it is mirrored to the DHT
// and the self-root companion is resealed best-effort when a backend is reachable
// (offline, the next write publishes and reseals).
func cmdDeviceInit(args []string) error {
	fs := flag.NewFlagSet("device init", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	signKeyFlag := fs.String("signkey", "", "master (owner) signing key (default <workspace>/keys/user.sign.key)")
	label := fs.String("label", "", "human-friendly label for this device (default the hostname)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	if ws.devicesPath() == "" {
		return fmt.Errorf("a bare root-file workspace has nowhere to store a device record; use a workspace folder (-root <dir>)")
	}
	if _, ok, err := ws.loadDeviceAuth(); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("this workspace already has a device record; use `device enroll`/`device revoke` to change it")
	}

	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(*signKeyFlag))
	if err != nil {
		return err
	}
	pub, err := thisDevicePub(ws)
	if err != nil {
		return err
	}
	lbl := *label
	if lbl == "" {
		if h, err := os.Hostname(); err == nil {
			lbl = h
		}
	}
	auth, err := device.Auth{}.With(pub, lbl)
	if err != nil {
		return err
	}
	auth = auth.Sign(signer)
	if err := ws.saveDeviceAuth(auth); err != nil {
		return err
	}

	fmt.Printf("Initialized device record at %s\n", ws.devicesPath())
	fmt.Printf("  this device: %s (%s)\n", device.NewID(pub).Short(), displayLabel(lbl))
	if err := deviceReseal(context.Background(), ws, signer, auth, *node, false); err != nil {
		return err
	}
	return nil
}

// cmdDeviceEnroll authorizes another device by its ML-KEM public key (read from a
// file, never a literal — matching `share -to`). It signs the advanced record with
// the master credential, saves it, then reseals the self-root companion to the new
// device set and republishes — so the enrolled device can open the current root
// immediately. This requires a DHT backend.
func cmdDeviceEnroll(args []string) error {
	fs := flag.NewFlagSet("device enroll", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	signKeyFlag := fs.String("signkey", "", "master (owner) signing key (default <workspace>/keys/user.sign.key)")
	label := fs.String("label", "", "human-friendly label for the enrolled device")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("enroll takes one <pubkey-file> (the device's ML-KEM public key, as written by keygen's .pub)")
	}
	newPub, err := resolveRecipient(fs.Arg(0))
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
	auth, ok, err := ws.loadDeviceAuth()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no device record in this workspace; run `device init` first")
	}
	if auth.Owner != signer.Public() {
		return fmt.Errorf("the device record is owned by a different identity; this signing key cannot change it")
	}
	updated, err := auth.With(newPub, *label)
	if err != nil {
		return err
	}
	updated = updated.Sign(signer)
	if err := ws.saveDeviceAuth(updated); err != nil {
		return err
	}

	fmt.Printf("Enrolled device %s (%s) — record advanced to seq %d\n",
		device.NewID(newPub).Short(), displayLabel(*label), updated.Seq)
	if err := deviceReseal(context.Background(), ws, signer, updated, *node, true); err != nil {
		return err
	}
	return nil
}

// cmdDeviceRevoke de-authorizes a device named by a full-or-prefix ID handle. It
// signs the advanced record with the master credential, saves it, then reseals the
// self-root companion to the *surviving* devices and advances the root — so the
// revoked device's key can no longer open the current root. Forward-only: bytes it
// already downloaded stay with it. Requires a DHT backend.
func cmdDeviceRevoke(args []string) error {
	fs := flag.NewFlagSet("device revoke", flag.ExitOnError)
	node := addBackendFlags(fs)
	rootFlag := fs.String("root", "", "workspace folder (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	signKeyFlag := fs.String("signkey", "", "master (owner) signing key (default <workspace>/keys/user.sign.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("revoke takes one <device-id> (full or prefix, as shown by `device list`)")
	}
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	signer, err := loadOrCreateSignKey(ws, ws.signKeyPath(*signKeyFlag))
	if err != nil {
		return err
	}
	auth, ok, err := ws.loadDeviceAuth()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no device record in this workspace; nothing to revoke")
	}
	if auth.Owner != signer.Public() {
		return fmt.Errorf("the device record is owned by a different identity; this signing key cannot change it")
	}
	m, err := auth.Resolve(fs.Arg(0))
	if err != nil {
		return err
	}
	updated, err := auth.Without(m.ID)
	if err != nil {
		return err
	}
	updated = updated.Sign(signer)
	if err := ws.saveDeviceAuth(updated); err != nil {
		return err
	}

	fmt.Printf("Revoked device %s (%s) — record advanced to seq %d, %d device(s) remain\n",
		m.ID.Short(), displayLabel(m.Label), updated.Seq, len(updated.Members))
	if err := deviceReseal(context.Background(), ws, signer, updated, *node, true); err != nil {
		return err
	}
	fmt.Println("The revoked device can no longer open the current root; already-downloaded data cannot be recalled.")
	return nil
}

// cmdDeviceList prints the currently authorized devices from the local record,
// marking this device.
func cmdDeviceList(args []string) error {
	fs := flag.NewFlagSet("device list", flag.ExitOnError)
	rootFlag := fs.String("root", "", "workspace folder (default $REVIKA_ROOT, else "+defaultWorkspaceDir+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ws, err := resolveWorkspace(*rootFlag)
	if err != nil {
		return err
	}
	auth, ok, err := ws.loadDeviceAuth()
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("No device record (legacy single-owner mode: every device shares the owner keys and none is individually revocable). Run `device init`.")
		return nil
	}
	var self device.ID
	haveSelf := false
	if pub, perr := thisDevicePub(ws); perr == nil {
		self, haveSelf = device.NewID(pub), true
	}
	fmt.Printf("Device record for %s (seq %d, %d device(s)):\n", auth.Owner, auth.Seq, len(auth.Members))
	for _, m := range auth.Members {
		marker := "  "
		if haveSelf && m.ID == self {
			marker = "* "
		}
		fmt.Printf("%s%s  added@seq %-3d  %s\n", marker, m.ID.Short(), m.Added, displayLabel(m.Label))
	}
	if haveSelf {
		fmt.Println("(* = this device)")
	}
	return nil
}

// deviceReseal mirrors the updated record to the DHT and reseals the self-root
// companion to its device set, advancing the root so the change takes effect. When
// requireNet is false (init) it degrades to a notice if no backend is configured;
// when true (enroll/revoke) a missing DHT backend is an error, since the reseal is
// what actually enacts the authorization change across devices.
func deviceReseal(ctx context.Context, ws *Workspace, signer cap.SignKey, auth device.Auth, node string, requireNet bool) error {
	eNode, eBootstrap := ws.backend(node)
	if eNode == "" && len(eBootstrap) == 0 {
		if requireNet {
			return fmt.Errorf("enroll/revoke needs a DHT backend to reseal and publish; select a workspace with bootstrap peers (-root) or pass -node")
		}
		fmt.Println("No backend configured; record saved locally. It will publish and reseal on your next write.")
		return nil
	}

	cfg := ws.pipelineConfig()
	s, closer, err := writeBackend(ctx, eNode, eBootstrap, signer, 0, cfg)
	if err != nil {
		if requireNet {
			return err
		}
		ctlLog.Warn("device: backend unavailable; record saved locally only", "event", "device.reseal", "err", err)
		return nil
	}
	defer closer()

	pub := rootPublisher(s)
	if pub == nil {
		if requireNet {
			return fmt.Errorf("enroll/revoke needs a DHT backend to reseal the self-root and publish the record; a single -node cannot")
		}
		fmt.Println("Backend is a single node, not the DHT; record saved locally. It will reseal on your next DHT write.")
		return nil
	}

	// Mirror the signed record to the DHT (best-effort: the local devices.json is
	// authoritative).
	if dp, ok := pub.(deviceAuthPublisher); ok {
		if err := dp.PutDeviceAuth(ctx, auth); err != nil {
			ctlLog.Warn("device: publish record to DHT failed", "event", "device.publish", "err", err)
		}
	}

	// Reseal the self-root companion to the new device set by re-committing the
	// current root: newCommitConfig reads the just-saved devices.json, so commitRoot
	// signs a fresh companion sealed to exactly these devices and advances the root.
	prev, exists, sealed, err := loadRoot(ws.RootFile, "")
	if err != nil {
		return err
	}
	if !exists {
		// Nothing published yet; the record alone governs the first write's seal.
		fmt.Println("No published root yet; the record will seal your namespace on the first write.")
		return nil
	}
	if sealed {
		return fmt.Errorf("cannot reseal on a shared, read-only root (%s)", ws.RootFile)
	}
	if prev.Owner != signer.Public() {
		return fmt.Errorf("root %s is owned by a different identity; this signing key cannot reseal it", ws.RootFile)
	}
	cc, err := ws.newCommitConfig(ws.RootFile, signer, s, cfg)
	if err != nil {
		return err
	}
	if err := commitRoot(ctx, cc, prev.Root, prev, exists, sealed, pub); err != nil {
		return err
	}
	fmt.Printf("Resealed the self-root companion to the current device set and advanced the root to seq %d.\n", prev.Seq+1)
	return nil
}

// displayLabel renders a device label for listings, substituting a placeholder for
// an empty one.
func displayLabel(label string) string {
	if label == "" {
		return "(unlabeled)"
	}
	return label
}
