// Command revika-client is a CLI for the revika namespace: cp, ls, pwd, and rm. It
// connects to an out-of-process storage adapter (e.g. revika-ipfs-adapter) over the
// rvk-plugin-v1 frame protocol, and keeps its signing identity, root pointer, and
// per-file content encryption keys in a local sqlite database. A path prefixed with
// "rvk:" refers to the revika namespace; any other path is local. For example,
// `revika-client cp rvk:foo.txt .` downloads foo.txt from revika to the local directory.
//
// Configuration is via flags or environment variables:
//
//	-addr / REVIKA_ADAPTER_ADDR      Adapter TCP address (default "localhost:9090").
//	-secret / REVIKA_ADAPTER_SECRET  Shared secret for the handshake (required).
//	-db / REVIKA_CLIENT_DB           sqlite database path (default $HOME/.config/revika/client.db).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/revika/revika/internal/db"
	"github.com/revika/revika/internal/netframe"
	"github.com/revika/revika/internal/provider"
	"github.com/revika/revika/internal/rootstore"
)

type config struct {
	addr   string
	secret string
	dbPath string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "revika-client: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, command, args, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if command == "" {
		return errors.New("usage: revika-client [-addr ADDR] [-secret SECRET] [-db PATH] <ls|pwd|cp|rm> [args...]")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	database, err := openDatabase(cfg.dbPath)
	if err != nil {
		return err
	}
	defer database.Close()

	signer, identityID, err := loadOrCreateSigner(database.DB)
	if err != nil {
		return err
	}

	client, err := netframe.Dial(ctx, cfg.addr, []byte(cfg.secret))
	if err != nil {
		return fmt.Errorf("connect to adapter at %s: %w", cfg.addr, err)
	}
	defer client.Close()

	roots := rootstore.NewSQLite(database.DB, identityID, signer.Public())
	prov, err := provider.New(ctx, client, signer, roots)
	if err != nil {
		return fmt.Errorf("open provider: %w", err)
	}

	switch command {
	case "ls":
		return runLS(ctx, prov, args)
	case "pwd":
		return runPWD()
	case "cp":
		return runCP(ctx, prov, database.DB, args)
	case "rm":
		return runRM(ctx, prov, database.DB, args)
	default:
		return fmt.Errorf("unknown command %q (want ls, pwd, cp, or rm)", command)
	}
}

// parseArgs consumes leading global flags, then returns the subcommand and its
// remaining arguments unparsed (paths may themselves look like flags, e.g. "-1").
func parseArgs(args []string) (config, string, []string, error) {
	flags := flag.NewFlagSet("revika-client", flag.ContinueOnError)
	addr := flags.String("addr", envOr("REVIKA_ADAPTER_ADDR", "localhost:9090"), "adapter TCP address")
	secret := flags.String("secret", os.Getenv("REVIKA_ADAPTER_SECRET"), "shared secret for the adapter handshake")
	dbPath := flags.String("db", envOr("REVIKA_CLIENT_DB", ""), "sqlite database path")
	if err := flags.Parse(args); err != nil {
		return config{}, "", nil, err
	}
	if *secret == "" {
		return config{}, "", nil, errors.New("-secret or REVIKA_ADAPTER_SECRET must be set")
	}
	path := *dbPath
	if path == "" {
		defaultPath, err := defaultDBPath()
		if err != nil {
			return config{}, "", nil, err
		}
		path = defaultPath
	}
	remaining := flags.Args()
	if len(remaining) == 0 {
		return config{addr: *addr, secret: *secret, dbPath: path}, "", nil, nil
	}
	return config{addr: *addr, secret: *secret, dbPath: path}, remaining[0], remaining[1:], nil
}

func defaultDBPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("determine default database path: %w", err)
	}
	return filepath.Join(configDir, "revika", "client.db"), nil
}

func openDatabase(path string) (*db.DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	database, err := db.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	return database, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
