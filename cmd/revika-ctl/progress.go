package main

// progress.go holds the small terminal helpers used to render an
// ssh-keygen-style progress display while an owner identity is being minted
// (see mintSigningKey in commands.go). None of this is load-bearing — it is
// purely presentation, and is skipped entirely when stderr is not a terminal.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// isTerminal reports whether f is a character device (a terminal), so the caller
// can choose between an animated in-place progress line and quiet output.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// spinnerFrames is a braille spinner; each frame is one grapheme so the line
// width stays stable as it animates.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinner picks a frame from elapsed time; the progress reporter ticks about
// every 100ms, so one frame per 100ms gives a smooth spin.
func spinner(elapsed time.Duration) string {
	return spinnerFrames[int(elapsed/(100*time.Millisecond))%len(spinnerFrames)]
}

// progressBar renders a fixed-width bar showing attempts against the expected
// ~2^difficulty count, plus a percentage. Proof-of-work is probabilistic, so
// attempts routinely run past the expectation — the bar caps at full while the
// percentage keeps counting up so a long-running mint still reads as "past due"
// rather than stalled.
func progressBar(attempts, expected uint64) string {
	const width = 20
	if expected == 0 {
		expected = 1
	}
	pct := attempts * 100 / expected
	filled := int(min(attempts*width/expected, width))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	return fmt.Sprintf("[%s] %d%%", bar, pct)
}

// humanCount formats n with thousands separators (e.g. 1234567 -> "1,234,567").
func humanCount(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	// Insert a comma every three digits from the right.
	head := len(s) % 3
	if head == 0 {
		head = 3
	}
	var b strings.Builder
	b.WriteString(s[:head])
	for i := head; i < len(s); i += 3 {
		b.WriteByte(',')
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// roundDuration trims a duration to a sensible display precision: tenths of a
// second under a minute, whole seconds beyond.
func roundDuration(d time.Duration) time.Duration {
	if d < time.Minute {
		return d.Round(100 * time.Millisecond)
	}
	return d.Round(time.Second)
}
