package daemon

import (
	"context"
	"errors"
	"time"
)

type Hooks struct {
	Sync        func(context.Context) error
	Maintenance func(context.Context) error
}

type Service struct {
	Hooks    Hooks
	Interval time.Duration
}

func (service Service) Run(ctx context.Context) error {
	if service.Hooks.Sync == nil {
		return errors.New("daemon: sync hook is required")
	}
	if service.Interval <= 0 {
		return errors.New("daemon: interval must be positive")
	}
	if err := service.cycle(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(service.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := service.cycle(ctx); err != nil {
				return err
			}
		}
	}
}

func (service Service) cycle(ctx context.Context) error {
	if err := service.Hooks.Sync(ctx); err != nil {
		return err
	}
	if service.Hooks.Maintenance != nil {
		return service.Hooks.Maintenance(ctx)
	}
	return nil
}
