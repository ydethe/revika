package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// StateFileName is the sidecar the reconciler keeps at the sync root recording
// the last point the two sides agreed (the base of the three-way merge). It is
// local bookkeeping, not part of the stored tree — like .git — so it is excluded
// from the scan. It holds only sizes, mtimes, and opaque version tokens (no
// decryption keys), but is written 0600 to stay consistent with revika's other
// local sidecars.
const StateFileName = ".revika-sync-state.json"

const stateVersion = 1

// baseEntry is the last-agreed state of one path: how the local side looked
// (kind + size + mtime) and how the remote side looked (its version tokens),
// captured at the moment the two agreed. A later scan compares against this to
// tell a genuine change from an unchanged file.
type baseEntry struct {
	Dir     bool   `json:"dir,omitempty"`
	Size    int64  `json:"size,omitempty"`
	MtimeNS int64  `json:"mtime_ns,omitempty"`
	Content []byte `json:"content,omitempty"` // remote ItemVersion.Content (base64)
	Meta    []byte `json:"meta,omitempty"`    // remote ItemVersion.Meta (base64)
}

// baseState is the persisted agreement: one entry per reconciled path.
type baseState struct {
	Version int                  `json:"version"`
	Entries map[string]baseEntry `json:"entries"`
}

// newBaseState returns an empty base.
func newBaseState() *baseState {
	return &baseState{Version: stateVersion, Entries: map[string]baseEntry{}}
}

// loadState reads the base sidecar at path. A missing file yields a fresh empty
// base (ok=false), so the first reconcile treats everything as new on whichever
// side it is present.
func loadState(path string) (*baseState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return newBaseState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("sync: read state %q: %w", path, err)
	}
	var st baseState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("sync: parse state %q: %w", path, err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("sync: state %q has unsupported version %d (want %d)", path, st.Version, stateVersion)
	}
	if st.Entries == nil {
		st.Entries = map[string]baseEntry{}
	}
	return &st, nil
}

// saveState atomically writes the base sidecar to path (write-temp-then-rename),
// 0600, so a crash mid-write never leaves a half-written base.
func saveState(path string, st *baseState) error {
	st.Version = stateVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("sync: encode state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".revika-sync-state-*.tmp")
	if err != nil {
		return fmt.Errorf("sync: create temp state: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync: chmod temp state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync: write temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("sync: close temp state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("sync: install state: %w", err)
	}
	return nil
}

// localMatchesBase reports whether a local entry is unchanged since the base:
// same kind, size, and mtime. A path absent from the base never "matches" (it is
// new), which the caller handles separately.
func (b baseEntry) localMatches(ls localState) bool {
	if (ls.kind == kindDir) != b.Dir {
		return false
	}
	if ls.kind == kindDir {
		return true // directories carry no content signal we track
	}
	return ls.size == b.Size && ls.mtimeNS == b.MtimeNS
}

// remoteMatchesBase reports whether a remote entry is unchanged since the base:
// identical content and metadata version tokens.
func (b baseEntry) remoteMatches(rs remoteState) bool {
	if (rs.kind == kindDir) != b.Dir {
		return false
	}
	return bytes.Equal(rs.content, b.Content) && bytes.Equal(rs.meta, b.Meta)
}

// agree builds the base entry recording that a local and remote entry are now in
// agreement (called after a successful sync of that path).
func agree(ls localState, rs remoteState) baseEntry {
	return baseEntry{
		Dir:     ls.kind == kindDir,
		Size:    ls.size,
		MtimeNS: ls.mtimeNS,
		Content: rs.content,
		Meta:    rs.meta,
	}
}
