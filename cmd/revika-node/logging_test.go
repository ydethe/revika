package main

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo}, // case-insensitive
		{" info ", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"trace", slog.LevelDebug}, // trace maps to debug
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
	}
	for _, c := range cases {
		got, err := parseLevel(c.in)
		if err != nil {
			t.Errorf("parseLevel(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	if _, err := parseLevel("nope"); err == nil {
		t.Error("parseLevel(nope): want error, got nil")
	}
}

func TestResolveFormat(t *testing.T) {
	// Explicit encodings resolve directly, case-insensitively.
	for in, want := range map[string]string{
		"json": "json", "JSON": "json",
		"text": "text", " Text ": "text",
	} {
		got, err := resolveFormat(in)
		if err != nil {
			t.Errorf("resolveFormat(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("resolveFormat(%q) = %q, want %q", in, got, want)
		}
	}

	// auto/"" resolve against whether stderr is a terminal. Under `go test`
	// stderr is a pipe, not a TTY, so both must resolve to json — but assert only
	// that the result is a valid encoder to stay robust if run attached to a TTY.
	for _, in := range []string{"", "auto", "AUTO"} {
		got, err := resolveFormat(in)
		if err != nil {
			t.Errorf("resolveFormat(%q): %v", in, err)
			continue
		}
		if got != "json" && got != "text" {
			t.Errorf("resolveFormat(%q) = %q, want json or text", in, got)
		}
	}

	if _, err := resolveFormat("yaml"); err == nil {
		t.Error("resolveFormat(yaml): want error, got nil")
	}
}

func TestNewLogger(t *testing.T) {
	for _, format := range []string{"json", "text", "auto"} {
		lg, err := newLogger(format, "info")
		if err != nil {
			t.Fatalf("newLogger(%q, info): %v", format, err)
		}
		if lg == nil {
			t.Fatalf("newLogger(%q, info): nil logger", format)
		}
		// The logger must be usable and honour the level.
		if !lg.Enabled(t.Context(), slog.LevelInfo) {
			t.Errorf("newLogger(%q): info level not enabled", format)
		}
	}

	// A debug logger enables debug; a default (info) one does not.
	if dbg, _ := newLogger("json", "debug"); !dbg.Enabled(t.Context(), slog.LevelDebug) {
		t.Error("debug logger does not enable debug level")
	}
	if inf, _ := newLogger("json", "info"); inf.Enabled(t.Context(), slog.LevelDebug) {
		t.Error("info logger unexpectedly enables debug level")
	}

	// Invalid level and format both surface as errors.
	if _, err := newLogger("json", "loud"); err == nil {
		t.Error("newLogger with bad level: want error")
	}
	if _, err := newLogger("brainfuck", "info"); err == nil {
		t.Error("newLogger with bad format: want error")
	}
}

func TestAlloyReplaceAttr(t *testing.T) {
	// The level value is lowercased so Grafana level detection works.
	got := alloyReplaceAttr(nil, slog.Any(slog.LevelKey, slog.LevelWarn))
	if s := got.Value.String(); s != "warn" {
		t.Errorf("alloyReplaceAttr level = %q, want %q", s, "warn")
	}

	// Non-level attrs pass through untouched.
	in := slog.String("event", "node.start")
	if out := alloyReplaceAttr(nil, in); out.Key != "event" || out.Value.String() != "node.start" {
		t.Errorf("alloyReplaceAttr mangled a non-level attr: %+v", out)
	}

	// A level *key* carrying a non-Level value is left alone (defensive branch).
	weird := slog.String(slog.LevelKey, "custom")
	if out := alloyReplaceAttr(nil, weird); out.Value.String() != "custom" {
		t.Errorf("alloyReplaceAttr changed a non-Level level value: %q", out.Value.String())
	}
}

func TestIsTerminal(t *testing.T) {
	// A pipe is not a terminal.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(w) {
		t.Error("isTerminal(pipe) = true, want false")
	}

	// A regular file is not a terminal either.
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("isTerminal(regular file) = true, want false")
	}

	// /dev/null is a character device but not a TTY on Linux — still not a
	// terminal for our purpose (we only care that a pipe/file returns false).
	if strings.Contains("", "") { // keep the import tidy without a runtime dep
		_ = f
	}
}
