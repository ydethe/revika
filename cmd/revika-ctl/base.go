package main

// base.go tracks this device's *merge base*: the root it last reconciled with
// the DHT, kept as a local, unsigned sidecar (`<workspace>/base.json`) beside
// root.json. commitRoot reads it to tell a genuine multi-device fork (the DHT
// root advanced against a subtree different from our base) from a plain local
// advance, and to give manifest.Merge3 its three-way common ancestor.
//
// It is per-device state: never signed, never shared, never published. Unlike
// the DHT root it retains the full key-bearing caps (like root.json, and equally
// secret — written 0600), because Merge3's cap-equality pruning compares keys;
// a key-stripped base would defeat every shortcut and manufacture spurious
// conflicts. A missing base.json is legal (a fresh or pre-upgrade device): the
// merge then runs against an empty ancestor, which unions both sides safely
// rather than dropping the remote.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"revika/internal/manifest"
)

// baseRecord is the on-disk merge-base: the full root cap this device last
// reconciled and the sequence it carried.
type baseRecord struct {
	Root manifest.ReadCap `json:"root"`
	Seq  uint64           `json:"seq"`
}

// loadBase reads the merge-base sidecar. ok is false when the file is absent (a
// fresh device or a pre-multi-device workspace); path == "" (file-mode root, no
// workspace dir) is treated the same way so callers need not special-case it.
func loadBase(path string) (baseRecord, bool, error) {
	if path == "" {
		return baseRecord{}, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return baseRecord{}, false, nil
		}
		return baseRecord{}, false, err
	}
	var r baseRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return baseRecord{}, false, fmt.Errorf("parse merge base %s: %w", path, err)
	}
	return r, true, nil
}

// saveBase writes the merge-base sidecar atomically-ish (temp + rename) at 0600.
// A "" path is a no-op (file-mode root has nowhere to keep per-device state).
func saveBase(path string, r baseRecord) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create base dir: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
