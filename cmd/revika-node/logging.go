package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// newLogger builds the node's structured logger.
//
// format selects the encoding:
//   - "json": one JSON object per line (time, level, msg, attrs). This is the
//     Grafana Alloy / Loki path — slog emits a native RFC3339Nano `time`, a
//     `level`, and a `msg`, which Alloy's loki.process `stage.json` parses
//     without extra regex. Every event also carries a stable `event` key
//     (e.g. "shard.put", "rebalance.move") for label extraction.
//   - "text": human-readable key=value (logfmt) lines for interactive use.
//   - "auto"/"": text when stderr is a terminal, json otherwise — so a node run
//     under systemd/docker (no TTY) logs JSON ready for collection while an
//     operator at a shell gets readable output.
//
// level is the minimum level: debug, info, warn, or error.
//
// The logger is tagged with service=revika-node so a shared Loki stream can be
// filtered per component. Per the dumb-node principle the node only ever logs
// metadata (shard content hashes, peer IDs, byte counts, load fractions) — never
// plaintext, keys, or decrypted content — so nothing here needs redaction.
func newLogger(format, level string) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	enc, err := resolveFormat(format)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: alloyReplaceAttr}
	var h slog.Handler
	switch enc {
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default: // "text"
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h).With("service", "revika-node"), nil
}

// resolveFormat maps the -log-format flag to a concrete encoder, resolving
// "auto" against whether stderr is a terminal.
func resolveFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "auto":
		if isTerminal(os.Stderr) {
			return "text", nil
		}
		return "json", nil
	case "json":
		return "json", nil
	case "text":
		return "text", nil
	default:
		return "", fmt.Errorf("unknown -log-format %q (want auto, text, or json)", format)
	}
}

// parseLevel maps the -log-level flag to a slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug", "trace":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown -log-level %q (want debug, info, warn, or error)", level)
	}
}

// alloyReplaceAttr normalizes the level value to lowercase ("info", not "INFO")
// so Grafana's level detection and Loki label extraction work out of the box.
// time and msg keep slog's defaults (RFC3339Nano `time`, `msg`).
func alloyReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if lvl, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(strings.ToLower(lvl.String()))
		}
	}
	return a
}

// isTerminal reports whether f is attached to a character device (a TTY),
// without pulling in x/term: a char-device mode bit is enough to tell an
// interactive console from a pipe, file, or the systemd journal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
