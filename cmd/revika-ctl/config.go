package main

// config.go adds the *workspace* concept: a single directory that groups
// everything one User needs to talk to a revika network — the connection
// profile (config.json), the mutable namespace anchor (root.json), and the
// User's keys (keys/). `connect` writes the profile; cp/ls/rm/share operate
// inside a workspace selected with -root <dir> (default .revika).
//
// -root is overloaded, backward-compatibly:
//   - a path that exists as a regular FILE is a bare root pointer — a plaintext
//     own root, or a sealed shared root opened with -key — with no surrounding
//     workspace and no config.json (the historical behaviour: backend and keys
//     must be given explicitly).
//   - a DIRECTORY (the default .revika, or any folder made by `connect`) is a
//     workspace: the root pointer is <dir>/root.json, keys default to
//     <dir>/keys/user.*, and <dir>/config.json (if present) supplies the
//     bootstrap peers, erasure parameters, and proof-of-work policy so commands
//     need no repeated -bootstrap/-k/-m flags.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"revika/internal/cap"
	"revika/internal/erasure"
	"revika/internal/pipeline"
)

const (
	defaultWorkspaceDir = ".revika"
	configFileName      = "config.json"
	rootFileName        = "root.json"
	keysSubdir          = "keys"
	keyBasename         = "user"
)

// Config is the connection profile written by `connect` and read by every
// namespace command in a workspace. It records how to reach the network
// (Bootstrap peers), how files are erasure-coded (Erasure: k data + m parity),
// the node's proof-of-work admission policy (PoW) so identities minted in this
// workspace satisfy it, and a human-friendly Label.
type Config struct {
	Label     string        `json:"label,omitempty"`
	Bootstrap []string      `json:"bootstrap"`
	Erasure   ErasureConfig `json:"erasure"`
	PoW       PoWConfig     `json:"pow"`
}

// ErasureConfig is the code rate this workspace stores files at: any K of K+M
// shards reconstruct a chunk.
type ErasureConfig struct {
	K int `json:"k"`
	M int `json:"m"`
}

// PoWConfig mirrors a node's proof-of-work admission policy for owner
// identities. Difficulty is leading zero bits (0 = the node enforces none);
// Puzzle is the grinding function ("argon2id" or "sha256").
type PoWConfig struct {
	Difficulty uint   `json:"difficulty"`
	Puzzle     string `json:"puzzle"`
}

// Workspace is the resolved -root: where the root pointer lives and, in
// workspace mode, the directory holding config.json and keys.
type Workspace struct {
	Dir      string  // directory holding config.json/root.json/keys
	RootFile string  // the root pointer file to load/save
	Config   *Config // parsed config.json; nil when absent or in file mode
	fileMode bool    // -root named a bare file, not a workspace directory
}

// resolveWorkspace turns a -root flag value into a Workspace. Precedence for the
// path is: the flag, then $REVIKA_ROOT, then the default .revika. A path that
// exists as a regular file is a bare root pointer (file mode); anything else is
// treated as a workspace directory and its config.json is loaded if present.
func resolveWorkspace(flagVal string) (*Workspace, error) {
	p := flagVal
	if p == "" {
		p = os.Getenv("REVIKA_ROOT")
	}
	if p == "" {
		p = defaultWorkspaceDir
	}
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		// A concrete file: a plaintext or sealed root pointer, no workspace.
		// Keys still fall back to the historical .revika/keys location.
		return &Workspace{Dir: defaultWorkspaceDir, RootFile: p, fileMode: true}, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ws := &Workspace{Dir: p, RootFile: filepath.Join(p, rootFileName)}
	cfg, err := loadConfig(filepath.Join(p, configFileName))
	if err != nil {
		return nil, err
	}
	ws.Config = cfg
	return ws, nil
}

// keyPrefix is the default path prefix for this workspace's identity files
// (<prefix>.key/.pub/.sign.key/.sign.pub).
func (w *Workspace) keyPrefix() string {
	return filepath.Join(w.Dir, keysSubdir, keyBasename)
}

// signKeyPath resolves the signing-key path: the explicit -signkey flag if set,
// else this workspace's default keys/user.sign.key.
func (w *Workspace) signKeyPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return w.keyPrefix() + ".sign.key"
}

// pipelineConfig starts from the pipeline defaults and applies this workspace's
// erasure parameters when its config.json set them.
func (w *Workspace) pipelineConfig() pipeline.Config {
	cfg := pipeline.DefaultConfig()
	if w != nil && w.Config != nil && w.Config.Erasure.K > 0 && w.Config.Erasure.M > 0 {
		cfg.Params = erasure.Params{K: w.Config.Erasure.K, M: w.Config.Erasure.M}
	}
	return cfg
}

// backend merges explicit -node/-bootstrap/-mdns flags with the workspace's
// saved bootstrap peers: any explicit selector wins outright; otherwise the
// config's bootstrap peers stand in so commands need no repeated flags.
func (w *Workspace) backend(node string, bootstrap []string, mdns bool) (string, []string, bool) {
	if node != "" || len(bootstrap) > 0 || mdns {
		return node, bootstrap, mdns
	}
	if w != nil && w.Config != nil && len(w.Config.Bootstrap) > 0 {
		return "", w.Config.Bootstrap, false
	}
	return node, bootstrap, mdns
}

// powSettings returns the proof-of-work puzzle and difficulty a newly minted
// identity in this workspace must satisfy: the workspace config's policy when it
// has one, else keygen's defaults (argon2id at 12 bits).
func (w *Workspace) powSettings() (cap.Puzzle, cap.Difficulty, error) {
	name, diff := "argon2id", uint(12)
	if w != nil && w.Config != nil {
		diff = w.Config.PoW.Difficulty
		if w.Config.PoW.Puzzle != "" {
			name = w.Config.PoW.Puzzle
		}
	}
	if diff > 255 {
		return nil, 0, fmt.Errorf("pow difficulty %d out of range (0-255)", diff)
	}
	puzzle, err := cap.PuzzleByName(name)
	if err != nil {
		return nil, 0, err
	}
	return puzzle, cap.Difficulty(diff), nil
}

// loadConfig reads config.json, returning (nil, nil) when the file is absent — a
// workspace directory without a saved profile is legal (keys/root still work).
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// saveConfig writes the connection profile as indented JSON, 0600 (it names the
// nodes this User places shards on).
func saveConfig(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// cmdConnect creates a workspace: a folder holding config.json (the connection
// profile — bootstrap peers, erasure k/m, the node's proof-of-work policy, and a
// label) alongside where root.json and the User's keys will live. It writes no
// keys itself; the identity is minted on the first write into the workspace
// (cp/rm/share), after a confirmation prompt, so `connect` stays a fast,
// network-free setup step.
func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	var bootstrap multiFlag
	fs.Var(&bootstrap, "bootstrap", "DHT bootstrap peer multiaddr (repeatable); the node(s) this workspace reaches the network through")
	dir := fs.String("root", defaultWorkspaceDir, "workspace folder to create (holds config.json, root.json, keys/)")
	label := fs.String("label", "", "human-friendly label for this connection")
	k := fs.Int("k", 4, "erasure data shards (any k of k+m reconstruct a chunk)")
	m := fs.Int("m", 2, "erasure parity shards")
	powDifficulty := fs.Uint("pow-difficulty", 0, "node's proof-of-work admission difficulty in leading zero bits; identities minted here will satisfy it (0 = node enforces none)")
	powPuzzle := fs.String("pow-puzzle", "argon2id", "node's proof-of-work puzzle: argon2id (memory-hard) or sha256")
	force := fs.Bool("force", false, "overwrite an existing config.json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Bootstrap peers may come from -bootstrap flags and/or positional args, so
	// `connect /ip4/…/p2p/…` reads naturally.
	boots := append([]string(bootstrap), fs.Args()...)
	if len(boots) == 0 {
		return fmt.Errorf("connect needs at least one bootstrap multiaddr (-bootstrap <ma> or a positional arg)")
	}
	if *k < 1 || *m < 1 {
		return fmt.Errorf("k and m must both be >= 1 (got k=%d m=%d)", *k, *m)
	}
	if (erasure.Params{K: *k, M: *m}).N() > 256 {
		return fmt.Errorf("k+m=%d exceeds 256", *k+*m)
	}
	if *powDifficulty > 255 {
		return fmt.Errorf("pow-difficulty %d out of range (0-255)", *powDifficulty)
	}
	if _, err := cap.PuzzleByName(*powPuzzle); err != nil {
		return err
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fmt.Errorf("create workspace %s: %w", *dir, err)
	}
	configPath := filepath.Join(*dir, configFileName)
	if _, err := os.Stat(configPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass -force to overwrite", configPath)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	cfg := Config{
		Label:     *label,
		Bootstrap: boots,
		Erasure:   ErasureConfig{K: *k, M: *m},
		PoW:       PoWConfig{Difficulty: *powDifficulty, Puzzle: *powPuzzle},
	}
	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}

	fmt.Printf("Workspace ready: %s\n", *dir)
	if *label != "" {
		fmt.Printf("  label:     %s\n", *label)
	}
	fmt.Printf("  bootstrap: %s\n", strings.Join(boots, ", "))
	fmt.Printf("  erasure:   %d data + %d parity (any %d of %d reconstruct)\n", *k, *m, *k, *k+*m)
	if *powDifficulty > 0 {
		fmt.Printf("  pow:       %s, %d bits\n", *powPuzzle, *powDifficulty)
	} else {
		fmt.Printf("  pow:       none\n")
	}
	fmt.Printf("\nEvery command targets it via -root %s (its default). Try:\n", *dir)
	fmt.Printf("  revika-ctl cp -root %s ./file rvk:docs/\n", *dir)
	fmt.Println("Your identity is created on the first write (you will be asked to confirm).")
	return nil
}
