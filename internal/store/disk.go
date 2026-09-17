package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Disk struct {
	root string
}

func NewDisk(root string) (*Disk, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	return &Disk{root: root}, nil
}

func (s *Disk) path(id ObjectID) string {
	name := sha256.Sum256([]byte(id))
	return filepath.Join(s.root, hex.EncodeToString(name[:])+".object")
}

func (s *Disk) Put(ctx context.Context, id ObjectID, content io.Reader) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	finalPath := s.path(id)
	temporary, err := os.CreateTemp(s.root, ".object-*")
	if err != nil {
		return fmt.Errorf("create temporary object: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if _, err := io.Copy(checkedWriter{ctx: ctx, writer: temporary}, content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary object: %w", err)
	}
	if _, err := os.Stat(finalPath); err == nil {
		return ErrAlreadyExists
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect object: %w", err)
	}
	if err := os.Chmod(temporaryName, 0o600); err != nil {
		return fmt.Errorf("protect object: %w", err)
	}
	if err := os.Rename(temporaryName, finalPath); err != nil {
		if os.IsExist(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("commit object: %w", err)
	}
	return nil
}

func (s *Disk) Get(ctx context.Context, id ObjectID) (io.ReadCloser, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	file, err := os.Open(s.path(id))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("open object: %w", err)
	}
	return file, nil
}

func (s *Disk) Has(ctx context.Context, id ObjectID) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	_, err := os.Stat(s.path(id))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect object: %w", err)
}

func (s *Disk) Delete(ctx context.Context, id ObjectID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := os.Remove(s.path(id)); os.IsNotExist(err) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("delete object: %w", err)
	}
	return nil
}

func (s *Disk) Close() error { return nil }

type checkedWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w checkedWriter) Write(data []byte) (int, error) {
	if err := checkContext(w.ctx); err != nil {
		return 0, err
	}
	return w.writer.Write(data)
}
