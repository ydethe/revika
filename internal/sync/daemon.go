package sync

import (
	"context"
	"time"
)

// Daemon runs a Reconciler on a fixed cadence: the "folder-watch" of the repo
// layout, implemented by polling rather than a kernel notification API so it
// stays pure-Go and portable (see the package doc). Each tick is one full
// Reconcile; ticks never overlap, because Reconcile holds the Reconciler's lock
// for the whole pass, so a long pass simply delays the next tick rather than
// piling up.
type Daemon struct {
	r        *Reconciler
	interval time.Duration
	onResult func(Result)
	onError  func(error)
}

// DaemonOption configures a Daemon.
type DaemonOption func(*Daemon)

// WithOnResult sets a callback invoked with the outcome of each completed pass.
func WithOnResult(fn func(Result)) DaemonOption { return func(d *Daemon) { d.onResult = fn } }

// WithOnError sets a callback invoked when a pass fails to scan or persist (a
// per-file error is reported through Result.Errors, not here).
func WithOnError(fn func(error)) DaemonOption { return func(d *Daemon) { d.onError = fn } }

// NewDaemon returns a Daemon that reconciles r every interval. interval must be
// positive.
func NewDaemon(r *Reconciler, interval time.Duration, opts ...DaemonOption) *Daemon {
	d := &Daemon{r: r, interval: interval}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Run reconciles immediately, then once per interval, until ctx is cancelled.
// It returns ctx.Err() when it stops. Scan/persist failures are surfaced through
// the WithOnError callback (or ignored if none is set) and do not stop the loop —
// a transient failure (e.g. a node briefly unreachable) should not tear down the
// daemon; the next tick retries.
func (d *Daemon) Run(ctx context.Context) error {
	d.tick(ctx)
	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			d.tick(ctx)
		}
	}
}

// tick runs one pass and dispatches its outcome to the callbacks.
func (d *Daemon) tick(ctx context.Context) {
	res, err := d.r.Reconcile(ctx)
	if err != nil {
		if d.onError != nil {
			d.onError(err)
		}
		return
	}
	if d.onResult != nil {
		d.onResult(res)
	}
}
