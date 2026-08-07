package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/device"
)

// deviceWorkspace builds a workspace directory wired to seedAddr: an identity
// under keys/user (pow disabled for speed) and a config.json naming the bootstrap
// peer, exactly as `connect` would leave it.
func deviceWorkspace(t *testing.T, seedAddr string) string {
	t.Helper()
	dir := t.TempDir()
	if err := cmdKeygen([]string{"-key", filepath.Join(dir, keysSubdir, keyBasename), "-pow-difficulty", "0"}); err != nil {
		t.Fatalf("keygen workspace: %v", err)
	}
	cfg := Config{Erasure: ErasureConfig{K: 4, M: 2}}
	if seedAddr != "" {
		cfg.Bootstrap = []string{seedAddr}
	}
	if err := saveConfig(filepath.Join(dir, configFileName), cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return dir
}

// mlkemPair loads an ML-KEM keypair written by keygen at <prefix>.key.
func mlkemPair(t *testing.T, keyFile string) (cap.PrivateKey, cap.PublicKey) {
	t.Helper()
	priv, err := readPrivateKey(keyFile)
	if err != nil {
		t.Fatalf("read %s: %v", keyFile, err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	return priv, pub
}

// TestDeviceInitListOffline exercises the record machinery with no network: a
// workspace without bootstrap peers can still init the record, and id/list report
// this device as the sole authorized member.
func TestDeviceInitListOffline(t *testing.T) {
	dir := t.TempDir()
	if err := cmdKeygen([]string{"-key", filepath.Join(dir, keysSubdir, keyBasename), "-pow-difficulty", "0"}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// No config.json → no backend; init must still write the record locally.

	capture(t, func() error { return cmdDevice([]string{"init", "-root", dir, "-label", "laptop"}) })

	if _, err := os.Stat(filepath.Join(dir, devicesFileName)); err != nil {
		t.Fatalf("devices.json not written: %v", err)
	}

	// A second init must refuse to clobber the record.
	if err := cmdDevice([]string{"init", "-root", dir}); err == nil {
		t.Fatal("second init should be refused")
	}

	out := capture(t, func() error { return cmdDevice([]string{"list", "-root", dir}) })
	if !strings.Contains(out, "laptop") || !strings.Contains(out, "this device") {
		t.Fatalf("list = %q, want the laptop entry marked as this device", out)
	}

	out = capture(t, func() error { return cmdDevice([]string{"id", "-root", dir}) })
	if !strings.Contains(out, "authorized") {
		t.Fatalf("id = %q, want it to report this device authorized", out)
	}
}

// TestDeviceEnrollRevokeReadRevocation is the read-side revocation crux over a
// real in-process DHT: after enrolling a second device it can open the self-root
// companion; after revoking it, it cannot, while the first device still can. This
// proves enroll/revoke reseal the companion to exactly the authorized set.
func TestDeviceEnrollRevokeReadRevocation(t *testing.T) {
	ctx := t.Context()
	seedAddr, _ := startStorageNode(t, ctx, "")

	ws := deviceWorkspace(t, seedAddr)
	ownerKeyPrefix := filepath.Join(ws, keysSubdir, keyBasename)
	owner, err := loadSignKey(ownerKeyPrefix + ".sign.key")
	if err != nil {
		t.Fatalf("load owner sign key: %v", err)
	}

	// Bootstrap the record with this (first) device.
	capture(t, func() error { return cmdDevice([]string{"init", "-root", ws}) })

	// Store a file so there is a root to seal. It goes straight to the seed via
	// -node (a single node reads shards back reliably in-process, without waiting on
	// DHT provider-record propagation); the root is not published to the DHT yet —
	// the first device enroll below publishes and seals it.
	src := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(src, bytes.Repeat([]byte("revika-device-"), 500), 0o644); err != nil {
		t.Fatal(err)
	}
	capture(t, func() error { return cmdCp([]string{"-node", seedAddr, "-root", ws, src, "rvk:docs/"}) })

	// A second device with its own ML-KEM keypair.
	dev2 := t.TempDir()
	if err := cmdKeygen([]string{"-key", filepath.Join(dev2, "user"), "-pow-difficulty", "0"}); err != nil {
		t.Fatalf("keygen dev2: %v", err)
	}
	dev2Priv, dev2Pub := mlkemPair(t, filepath.Join(dev2, "user.key"))

	// Enroll it: the companion is resealed to {device1, device2} and (first) published.
	capture(t, func() error {
		return cmdDevice([]string{"enroll", "-root", ws, "-label", "phone", filepath.Join(dev2, "user.pub")})
	})
	if !deviceCanOpen(t, ctx, seedAddr, owner.Public(), dev2Priv, dev2Pub) {
		t.Fatal("enrolled device could not open the companion")
	}

	// Revoke it: the companion is resealed to the survivor {device1} only.
	id := device.NewID(dev2Pub).String()
	capture(t, func() error { return cmdDevice([]string{"revoke", "-root", ws, id}) })
	if deviceCanOpen(t, ctx, seedAddr, owner.Public(), dev2Priv, dev2Pub) {
		t.Fatal("revoked device can still open the current companion (read revocation failed)")
	}

	// The first device (the owner ML-KEM key) must still be able to read.
	d1Priv, d1Pub := mlkemPair(t, ownerKeyPrefix+".key")
	if !deviceCanOpen(t, ctx, seedAddr, owner.Public(), d1Priv, d1Pub) {
		t.Fatal("surviving device lost access after a revoke")
	}
}

// deviceCanOpen reports whether (priv,pub) can open owner's currently published
// self-root companion via the DHT — the exact test a device does when rebuilding
// the User's namespace on another machine.
func deviceCanOpen(t *testing.T, ctx context.Context, seedAddr string, owner cap.SignPubKey, priv cap.PrivateKey, pub cap.PublicKey) bool {
	t.Helper()
	_, disc, closer, err := joinDHT(ctx, []string{seedAddr})
	if err != nil {
		t.Fatalf("joinDHT: %v", err)
	}
	defer closer()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rp, ok, err := disc.GetRoot(cctx, owner)
	if err != nil || !ok {
		t.Fatalf("GetRoot: ok=%v err=%v", ok, err)
	}
	_, ok, err = disc.GetFullRoot(cctx, owner, priv, pub, rp.Root)
	return ok && err == nil
}
