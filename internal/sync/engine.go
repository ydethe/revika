package sync

import (
	"context"
	"errors"
	"io"

	"github.com/revika/revika/internal/provider"
)

var ErrConflict = errors.New("sync: local mutation conflicted")

type AnchorStore interface {
	Load(ctx context.Context) (provider.SyncAnchor, error)
	Save(ctx context.Context, anchor provider.SyncAnchor) error
}

type Surface interface {
	ApplyRemote(ctx context.Context, changes []provider.Change) error
	Pending(ctx context.Context) ([]Mutation, error)
	Acknowledge(ctx context.Context, mutations []Mutation) error
	Conflict(ctx context.Context, mutation Mutation, sequence uint64) error
}

type MutationType uint8

const (
	MutationCreate MutationType = iota
	MutationModify
	MutationDelete
	MutationRename
)

type Mutation struct {
	Type     MutationType
	ID       provider.ItemID
	Parent   provider.ItemID
	Name     string
	Contents []byte
	Meta     *provider.Metadata
}

type Engine struct {
	Provider provider.Provider
	Surface  Surface
	Anchors  AnchorStore
}

func (engine Engine) Sync(ctx context.Context) error {
	if engine.Provider == nil || engine.Surface == nil || engine.Anchors == nil {
		return errors.New("sync: provider, surface, and anchors are required")
	}
	anchor, err := engine.Anchors.Load(ctx)
	if err != nil {
		return err
	}
	changes, err := engine.Provider.EnumerateChanges(ctx, anchor)
	if err != nil {
		return err
	}
	if err := engine.Surface.ApplyRemote(ctx, changes.Changes); err != nil {
		return err
	}
	mutations, err := engine.Surface.Pending(ctx)
	if err != nil {
		return err
	}
	for _, mutation := range mutations {
		if err := engine.applyMutation(ctx, mutation); err != nil {
			if conflictErr := engine.Surface.Conflict(ctx, mutation, changes.Anchor.Sequence); conflictErr != nil {
				return conflictErr
			}
			return errors.Join(ErrConflict, err)
		}
	}
	if err := engine.Surface.Acknowledge(ctx, mutations); err != nil {
		return err
	}
	current, err := engine.Provider.CurrentAnchor(ctx)
	if err != nil {
		return err
	}
	return engine.Anchors.Save(ctx, current)
}

func (engine Engine) applyMutation(ctx context.Context, mutation Mutation) error {
	switch mutation.Type {
	case MutationCreate:
		_, err := engine.Provider.CreateItem(ctx, mutation.Parent, provider.CreateRequest{Name: mutation.Name, Meta: metadataOrZero(mutation.Meta), Contents: bytesReader(mutation.Contents)})
		return err
	case MutationModify:
		_, err := engine.Provider.ModifyItem(ctx, mutation.ID, provider.ModifyRequest{Contents: bytesReader(mutation.Contents), Meta: mutation.Meta})
		return err
	case MutationDelete:
		return engine.Provider.DeleteItem(ctx, mutation.ID)
	case MutationRename:
		_, err := engine.Provider.Rename(ctx, mutation.ID, mutation.Parent, mutation.Name)
		return err
	default:
		return errors.New("sync: unknown mutation type")
	}
}

func metadataOrZero(metadata *provider.Metadata) provider.Metadata {
	if metadata == nil {
		return provider.Metadata{}
	}
	return *metadata
}

type byteReader struct {
	data []byte
	read bool
}

func bytesReader(data []byte) *byteReader { return &byteReader{data: append([]byte(nil), data...)} }

func (reader *byteReader) Read(destination []byte) (int, error) {
	if reader.read {
		return 0, io.EOF
	}
	reader.read = true
	copyCount := copy(destination, reader.data)
	if copyCount < len(reader.data) {
		reader.data = reader.data[copyCount:]
		reader.read = false
	}
	return copyCount, nil
}

type MemoryAnchorStore struct {
	anchor provider.SyncAnchor
}

func (store *MemoryAnchorStore) Load(ctx context.Context) (provider.SyncAnchor, error) {
	if err := contextError(ctx); err != nil {
		return provider.SyncAnchor{}, err
	}
	return provider.SyncAnchor{Sequence: store.anchor.Sequence, Root: append([]byte(nil), store.anchor.Root...)}, nil
}

func (store *MemoryAnchorStore) Save(ctx context.Context, anchor provider.SyncAnchor) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	store.anchor = provider.SyncAnchor{Sequence: anchor.Sequence, Root: append([]byte(nil), anchor.Root...)}
	return nil
}

func contextError(ctx context.Context) error {
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
