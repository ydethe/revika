package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"revika/internal/cap"
	"revika/internal/manifest"
)

// FileRootStore is a RootStore that persists the User's signed RootPointer to a
// local JSON file (default `.revika/root.json`). It is the single-process,
// on-disk counterpart of MemRootStore: it gives revika-ctl a durable namespace
// anchor between invocations, and slots into the same RootStore seam the planned
// DHT publisher will fill (see the interface doc). A root is visible only where
// its file lives until that networked store lands.
//
// The file holds a *plaintext* RootPointer — the User's own, mutable namespace.
// A tree shared *with* a User is a different artifact (a RootPointer sealed to
// them with ML-KEM-768, opened with their private key); that lives outside this
// store, which never writes anything but its owner's pointer.
//
// Defence controls (security/Defence.md; primitive P3 in security/frameworks.md):
//
//	SC-28 (Protection of Information at Rest) — the file names the root cap, which unlocks
//	      the whole namespace, so it is written 0600 under a 0700 dir (as secret as a manifest).
//	SC-8  (Transmission Integrity) — Save rejects a non-advancing Seq (anti-rollback), mirroring
//	      the rule the networked store will enforce; Load verifies the Ed25519 signature.
type FileRootStore struct {
	path string
}

// NewFileRootStore returns a RootStore backed by the file at path.
func NewFileRootStore(path string) *FileRootStore { return &FileRootStore{path: path} }

// Path reports the file the store reads and writes.
func (f *FileRootStore) Path() string { return f.path }

// rootPointerJSON is the on-disk shape: fixed-width byte fields render as base64
// (JSON has no byte-string type), the root cap marshals itself (hex), and the
// counters are plain numbers.
type rootPointerJSON struct {
	Owner  string           `json:"owner"` // base64 Ed25519 owner pubkey
	Root   manifest.ReadCap `json:"root"`
	Seq    uint64           `json:"seq"`
	TimeNS int64            `json:"time_ns"`
	Sig    string           `json:"sig"` // base64 Ed25519 signature
}

// EncodeRootPointer renders rp as the indented JSON a root file holds. It is
// exported so a shared-root artifact (a RootPointer sealed to a recipient) can
// reuse the same codec the store writes.
func EncodeRootPointer(rp manifest.RootPointer) ([]byte, error) {
	return json.MarshalIndent(rootPointerJSON{
		Owner:  base64.StdEncoding.EncodeToString(rp.Owner[:]),
		Root:   rp.Root,
		Seq:    rp.Seq,
		TimeNS: rp.TimeNS,
		Sig:    base64.StdEncoding.EncodeToString(rp.Sig),
	}, "", "  ")
}

// DecodeRootPointer reverses EncodeRootPointer. It does not verify the signature;
// callers do (Load does, so does a reader of a shared root).
func DecodeRootPointer(data []byte) (manifest.RootPointer, error) {
	var jr rootPointerJSON
	if err := json.Unmarshal(data, &jr); err != nil {
		return manifest.RootPointer{}, fmt.Errorf("provider: parse root pointer: %w", err)
	}
	owner, err := base64.StdEncoding.DecodeString(jr.Owner)
	if err != nil || len(owner) != len(cap.SignPubKey{}) {
		return manifest.RootPointer{}, fmt.Errorf("provider: root pointer has a malformed owner key")
	}
	sig, err := base64.StdEncoding.DecodeString(jr.Sig)
	if err != nil {
		return manifest.RootPointer{}, fmt.Errorf("provider: root pointer has a malformed signature")
	}
	rp := manifest.RootPointer{Root: jr.Root, Seq: jr.Seq, TimeNS: jr.TimeNS, Sig: sig}
	copy(rp.Owner[:], owner)
	return rp, nil
}

// Load implements RootStore. ok is false when no file exists yet (a fresh
// namespace). A present-but-invalid signature is an error, not a fresh start, so
// a tampered pointer can never be silently replaced.
func (f *FileRootStore) Load(ctx context.Context) (manifest.RootPointer, bool, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return manifest.RootPointer{}, false, nil
		}
		return manifest.RootPointer{}, false, err
	}
	rp, err := DecodeRootPointer(data)
	if err != nil {
		return manifest.RootPointer{}, false, err
	}
	if !rp.Verify() {
		return manifest.RootPointer{}, false, fmt.Errorf("provider: root pointer %s failed signature verification", f.path)
	}
	return rp, true, nil
}

// Save implements RootStore. It rejects a pointer that does not advance the
// stored Seq, or that is signed by a different owner than the stored one, and
// writes atomically-ish (temp file + rename) at 0600.
func (f *FileRootStore) Save(ctx context.Context, rp manifest.RootPointer) error {
	if !rp.Verify() {
		return fmt.Errorf("provider: refusing to save an unsigned or invalid root pointer")
	}
	if cur, ok, err := f.Load(ctx); err != nil {
		return err
	} else if ok {
		if cur.Owner != rp.Owner {
			return fmt.Errorf("provider: root pointer owner mismatch (stored root belongs to a different identity)")
		}
		if rp.Seq <= cur.Seq {
			return fmt.Errorf("provider: root pointer seq %d does not advance stored seq %d", rp.Seq, cur.Seq)
		}
	}
	data, err := EncodeRootPointer(rp)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(f.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("provider: create root dir: %w", err)
		}
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}
