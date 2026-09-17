package store

import (
	"context"
	"errors"
	"io"
)

var (
	ErrNotFound      = errors.New("store: object not found")
	ErrAlreadyExists = errors.New("store: object already exists")
)

type ObjectID string

type Store interface {
	Put(ctx context.Context, id ObjectID, content io.Reader) error
	Get(ctx context.Context, id ObjectID) (io.ReadCloser, error)
	Has(ctx context.Context, id ObjectID) (bool, error)
	Delete(ctx context.Context, id ObjectID) error
	Close() error
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
