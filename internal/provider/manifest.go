package provider

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/revika/revika/internal/crypto"
	"github.com/revika/revika/internal/manifest"
	"github.com/revika/revika/internal/rootstore"
	"github.com/revika/revika/internal/store"
)

type Manifest struct {
	*Memory
	objects store.Store
	root    rootstore.Store
	signer  crypto.Signer
	clock   func() int64
}

func New(ctx context.Context, objects store.Store, signer crypto.Signer, roots rootstore.Store) (*Manifest, error) {
	return NewWithClock(ctx, objects, signer, roots, func() int64 { return time.Now().UnixNano() })
}

func NewWithClock(ctx context.Context, objects store.Store, signer crypto.Signer, roots rootstore.Store, clock func() int64) (*Manifest, error) {
	if objects == nil || signer == nil || roots == nil || clock == nil {
		return nil, errors.New("provider: manifest dependencies are required")
	}
	provider := &Manifest{Memory: NewMemory(), objects: objects, root: roots, signer: signer, clock: clock}
	pointer, ok, err := roots.Load(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		if err := provider.persist(ctx); err != nil {
			return nil, err
		}
		return provider, nil
	}
	if err := rootstore.Validate(pointer, signer.Public()); err != nil {
		return nil, err
	}
	if err := provider.loadSnapshot(ctx, string(pointer.Root)); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *Manifest) CreateItem(ctx context.Context, parent ItemID, request CreateRequest) (Item, error) {
	item, err := p.Memory.CreateItem(ctx, parent, request)
	if err != nil {
		return Item{}, err
	}
	if err := p.persist(ctx); err != nil {
		return Item{}, err
	}
	return item, nil
}

func (p *Manifest) ModifyItem(ctx context.Context, id ItemID, request ModifyRequest) (Item, error) {
	item, err := p.Memory.ModifyItem(ctx, id, request)
	if err != nil {
		return Item{}, err
	}
	if request.Contents == nil && request.Meta == nil {
		return item, nil
	}
	if err := p.persist(ctx); err != nil {
		return Item{}, err
	}
	return item, nil
}

func (p *Manifest) DeleteItem(ctx context.Context, id ItemID) error {
	if err := p.Memory.DeleteItem(ctx, id); err != nil {
		return err
	}
	return p.persist(ctx)
}

func (p *Manifest) Rename(ctx context.Context, id ItemID, newParent ItemID, newName string) (Item, error) {
	item, err := p.Memory.Rename(ctx, id, newParent, newName)
	if err != nil {
		return Item{}, err
	}
	if err := p.persist(ctx); err != nil {
		return Item{}, err
	}
	return item, nil
}

type manifestSnapshot struct {
	Items    map[ItemID]Item
	Contents map[ItemID][]byte
	Events   []manifestEvent
	Sequence uint64
	NextID   uint64
}

type manifestEvent struct {
	Sequence uint64
	Change   Change
}

func (p *Manifest) persist(ctx context.Context) error {
	p.mu.RLock()
	snapshot := manifestSnapshot{
		Items:    snapshotItems(p.items),
		Contents: cloneContents(p.contents),
		Events:   snapshotEvents(p.events),
		Sequence: p.sequence,
		NextID:   p.nextID,
	}
	p.mu.RUnlock()
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	address, err := manifest.Save(ctx, p.objects, manifest.NewFile(nil, data))
	if err != nil {
		return err
	}
	pointer, err := rootstore.NewPointer(p.signer, snapshot.Sequence, p.clock(), []byte(address))
	if err != nil {
		return err
	}
	return p.root.Save(ctx, pointer)
}

func (p *Manifest) loadSnapshot(ctx context.Context, address string) error {
	node, err := manifest.Load(ctx, p.objects, address)
	if err != nil {
		return err
	}
	if node.Kind != manifest.KindFile {
		return manifest.ErrInvalidNode
	}
	var snapshot manifestSnapshot
	if err := json.Unmarshal(node.Content, &snapshot); err != nil {
		return err
	}
	if snapshot.Items == nil || snapshot.NextID == 0 {
		return manifest.ErrInvalidNode
	}
	p.mu.Lock()
	p.items = restoreItems(snapshot.Items)
	p.contents = snapshot.Contents
	p.events = restoreEvents(snapshot.Events)
	p.sequence = snapshot.Sequence
	p.nextID = snapshot.NextID
	p.recomputeRoot()
	p.mu.Unlock()
	return nil
}

func snapshotItems(items map[ItemID]*memoryItem) map[ItemID]Item {
	result := make(map[ItemID]Item, len(items))
	for id, item := range items {
		result[id] = cloneItem(item.item)
	}
	return result
}

func restoreItems(items map[ItemID]Item) map[ItemID]*memoryItem {
	result := make(map[ItemID]*memoryItem, len(items))
	for id, item := range items {
		cloned := cloneItem(item)
		result[id] = &memoryItem{item: cloned}
	}
	return result
}

func cloneContents(contents map[ItemID][]byte) map[ItemID][]byte {
	result := make(map[ItemID][]byte, len(contents))
	for id, content := range contents {
		result[id] = append([]byte(nil), content...)
	}
	return result
}

func snapshotEvents(events []memoryEvent) []manifestEvent {
	result := make([]manifestEvent, len(events))
	for index, event := range events {
		result[index] = manifestEvent{Sequence: event.sequence, Change: cloneChange(event.change)}
	}
	return result
}

func restoreEvents(events []manifestEvent) []memoryEvent {
	result := make([]memoryEvent, len(events))
	for index, event := range events {
		result[index] = memoryEvent{sequence: event.Sequence, change: cloneChange(event.Change)}
	}
	return result
}

var _ Provider = (*Manifest)(nil)
