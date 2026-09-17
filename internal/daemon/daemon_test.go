package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceRunsHooksUntilCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var syncCalls atomic.Int32
	var maintenanceCalls atomic.Int32
	service := Service{Interval: time.Millisecond, Hooks: Hooks{
		Sync: func(context.Context) error {
			syncCalls.Add(1)
			return nil
		},
		Maintenance: func(context.Context) error {
			maintenanceCalls.Add(1)
			if maintenanceCalls.Load() >= 2 {
				cancel()
			}
			return nil
		},
	}}
	err := service.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if syncCalls.Load() < 2 || maintenanceCalls.Load() < 2 {
		t.Fatalf("hook calls = sync %d/maintenance %d, want at least 2 each", syncCalls.Load(), maintenanceCalls.Load())
	}
}
