package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
)

type Memory struct {
	mu       sync.RWMutex
	items    map[ItemID]*memoryItem
	contents map[ItemID][]byte
	events   []memoryEvent
	sequence uint64
	nextID   uint64
	root     []byte
}

type memoryItem struct {
	item Item
}

type memoryEvent struct {
	sequence uint64
	change   Change
}

func NewMemory() *Memory {
	provider := &Memory{
		items:    make(map[ItemID]*memoryItem),
		contents: make(map[ItemID][]byte),
		nextID:   1,
	}
	provider.items[RootID] = &memoryItem{item: Item{ID: RootID, IsDir: true, Caps: CapRead | CapEnumerate | CapAddSubItems}}
	provider.sequence = 1
	provider.recomputeRoot()
	return provider
}

func (p *Memory) Root(ctx context.Context) (ItemID, error) {
	if err := checkContext(ctx); err != nil {
		return "", err
	}
	return RootID, nil
}

func (p *Memory) Stat(ctx context.Context, id ItemID) (Item, error) {
	if err := checkContext(ctx); err != nil {
		return Item{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.itemLocked(id)
}

func (p *Memory) Lookup(ctx context.Context, parent ItemID, name string) (Item, error) {
	if err := checkContext(ctx); err != nil {
		return Item{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	parentItem, err := p.itemLocked(parent)
	if err != nil {
		return Item{}, err
	}
	if !parentItem.IsDir {
		return Item{}, ErrInvalidData
	}
	for _, candidate := range p.items {
		if candidate.item.Parent == parent && candidate.item.Name == name {
			return cloneItem(candidate.item), nil
		}
	}
	return Item{}, ErrNotFound
}

func (p *Memory) Enumerate(ctx context.Context, directory ItemID) ([]Item, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	item, err := p.itemLocked(directory)
	if err != nil {
		return nil, err
	}
	if !item.IsDir {
		return nil, ErrInvalidData
	}
	result := make([]Item, 0)
	for _, candidate := range p.items {
		if candidate.item.Parent == directory {
			result = append(result, cloneItem(candidate.item))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result, nil
}

func (p *Memory) CurrentAnchor(ctx context.Context) (SyncAnchor, error) {
	if err := checkContext(ctx); err != nil {
		return SyncAnchor{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return SyncAnchor{Sequence: p.sequence, Root: append([]byte(nil), p.root...)}, nil
}

func (p *Memory) EnumerateChanges(ctx context.Context, since SyncAnchor) (ChangeSet, error) {
	if err := checkContext(ctx); err != nil {
		return ChangeSet{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if since.Sequence > p.sequence {
		return ChangeSet{}, ErrInvalidData
	}
	changes := make([]Change, 0)
	for _, event := range p.events {
		if event.sequence > since.Sequence {
			changes = append(changes, cloneChange(event.change))
		}
	}
	return ChangeSet{Changes: changes, Anchor: SyncAnchor{Sequence: p.sequence, Root: append([]byte(nil), p.root...)}}, nil
}

func (p *Memory) FetchContents(ctx context.Context, id ItemID, destination io.Writer) (ItemVersion, error) {
	if err := checkContext(ctx); err != nil {
		return ItemVersion{}, err
	}
	p.mu.RLock()
	item, err := p.itemLocked(id)
	data := append([]byte(nil), p.contents[id]...)
	p.mu.RUnlock()
	if err != nil {
		return ItemVersion{}, err
	}
	if item.IsDir || item.IsLink {
		return item.Version, nil
	}
	if _, err := io.Copy(checkedWriter{ctx: ctx, destination: destination}, bytes.NewReader(data)); err != nil {
		return ItemVersion{}, err
	}
	return item.Version, nil
}

func (p *Memory) Evict(ctx context.Context, id ItemID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	_, err := p.Stat(ctx, id)
	return err
}

func (p *Memory) CreateItem(ctx context.Context, parent ItemID, request CreateRequest) (Item, error) {
	if err := checkContext(ctx); err != nil {
		return Item{}, err
	}
	data, err := readContents(ctx, request.Contents)
	if err != nil {
		return Item{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateName(request.Name); err != nil {
		return Item{}, err
	}
	parentItem, err := p.itemLocked(parent)
	if err != nil {
		return Item{}, err
	}
	if !parentItem.IsDir {
		return Item{}, ErrInvalidData
	}
	if p.hasChildLocked(parent, request.Name) {
		return Item{}, fmt.Errorf("provider: item %q already exists", request.Name)
	}
	id := ItemID(fmt.Sprintf("item-%d", p.nextID))
	p.nextID++
	item := Item{ID: id, Parent: parent, Name: request.Name, IsDir: request.IsDir, IsLink: request.Meta.SymlinkTarget != "", Meta: cloneMetadata(request.Meta)}
	item.Caps = CapRead | CapRename | CapReparent | CapDelete
	if request.IsDir {
		item.Caps |= CapEnumerate | CapAddSubItems
	} else {
		item.Caps |= CapWrite
		p.contents[id] = data
	}
	item.Size = int64(len(data))
	item.Version = makeVersion(data, item.Meta)
	p.items[id] = &memoryItem{item: item}
	p.commitLocked(Change{Type: ChangeAdded, ID: id, Path: p.pathLocked(id), Item: &item})
	return cloneItem(item), nil
}

func (p *Memory) ModifyItem(ctx context.Context, id ItemID, request ModifyRequest) (Item, error) {
	if err := checkContext(ctx); err != nil {
		return Item{}, err
	}
	data, err := readContents(ctx, request.Contents)
	if err != nil {
		return Item{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current, err := p.itemLocked(id)
	if err != nil {
		return Item{}, err
	}
	if request.Contents == nil && request.Meta == nil {
		return current, nil
	}
	if request.Contents != nil {
		p.contents[id] = data
		current.Size = int64(len(data))
	}
	if request.Meta != nil {
		current.Meta = cloneMetadata(*request.Meta)
		current.IsLink = current.Meta.SymlinkTarget != ""
	}
	current.Version = makeVersion(p.contents[id], current.Meta)
	p.items[id] = &memoryItem{item: current}
	p.commitLocked(Change{Type: ChangeModified, ID: id, Path: p.pathLocked(id), Item: &current})
	return cloneItem(current), nil
}

func (p *Memory) DeleteItem(ctx context.Context, id ItemID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if id == RootID {
		return ErrInvalidData
	}
	if _, err := p.itemLocked(id); err != nil {
		return err
	}
	ids := p.descendantsLocked(id)
	for _, childID := range ids {
		path := p.pathLocked(childID)
		delete(p.items, childID)
		delete(p.contents, childID)
		p.commitLocked(Change{Type: ChangeDeleted, ID: childID, Path: path})
	}
	return nil
}

func (p *Memory) Rename(ctx context.Context, id ItemID, newParent ItemID, newName string) (Item, error) {
	if err := checkContext(ctx); err != nil {
		return Item{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateName(newName); err != nil {
		return Item{}, err
	}
	item, err := p.itemLocked(id)
	if err != nil {
		return Item{}, err
	}
	parent, err := p.itemLocked(newParent)
	if err != nil {
		return Item{}, err
	}
	if !parent.IsDir || p.hasChildLocked(newParent, newName) {
		return Item{}, ErrInvalidData
	}
	item.Parent = newParent
	item.Name = newName
	p.items[id] = &memoryItem{item: item}
	p.commitLocked(Change{Type: ChangeModified, ID: id, Path: p.pathLocked(id), Item: &item})
	return cloneItem(item), nil
}

func (p *Memory) itemLocked(id ItemID) (Item, error) {
	item, ok := p.items[id]
	if !ok {
		return Item{}, ErrNotFound
	}
	return cloneItem(item.item), nil
}

func (p *Memory) validateName(name string) error {
	if name == "" || name == "." || name == ".." || bytes.ContainsAny([]byte(name), "/\\") {
		return ErrInvalidData
	}
	return nil
}

func (p *Memory) hasChildLocked(parent ItemID, name string) bool {
	for _, item := range p.items {
		if item.item.Parent == parent && item.item.Name == name {
			return true
		}
	}
	return false
}

func (p *Memory) descendantsLocked(id ItemID) []ItemID {
	result := []ItemID{id}
	for index := 0; index < len(result); index++ {
		for childID, item := range p.items {
			if item.item.Parent == result[index] {
				result = append(result, childID)
			}
		}
	}
	return result
}

func (p *Memory) pathLocked(id ItemID) string {
	parts := make([]string, 0)
	for id != RootID {
		item, ok := p.items[id]
		if !ok {
			break
		}
		parts = append(parts, item.item.Name)
		id = item.item.Parent
	}
	for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
		parts[left], parts[right] = parts[right], parts[left]
	}
	path := ""
	for _, part := range parts {
		path += "/" + part
	}
	return path
}

func (p *Memory) commitLocked(change Change) {
	p.sequence++
	p.recomputeRoot()
	p.events = append(p.events, memoryEvent{sequence: p.sequence, change: cloneChange(change)})
}

func (p *Memory) recomputeRoot() {
	ids := make([]string, 0, len(p.items))
	for id := range p.items {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	hash := sha256.New()
	for _, id := range ids {
		item := p.items[ItemID(id)].item
		encoded, _ := json.Marshal(item)
		hash.Write(encoded)
		hash.Write(p.contents[item.ID])
	}
	p.root = hash.Sum(nil)
}

func makeVersion(content []byte, metadata Metadata) ItemVersion {
	contentDigest := sha256.Sum256(content)
	metadataBytes, _ := json.Marshal(metadata)
	metadataDigest := sha256.Sum256(metadataBytes)
	return ItemVersion{Content: contentDigest[:], Meta: metadataDigest[:]}
}

func readContents(ctx context.Context, source io.Reader) ([]byte, error) {
	if source == nil {
		return nil, nil
	}
	return io.ReadAll(checkedReader{ctx: ctx, reader: source})
}

type checkedReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader checkedReader) Read(data []byte) (int, error) {
	if err := checkContext(reader.ctx); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

type checkedWriter struct {
	ctx         context.Context
	destination io.Writer
}

func (writer checkedWriter) Write(data []byte) (int, error) {
	if err := checkContext(writer.ctx); err != nil {
		return 0, err
	}
	return writer.destination.Write(data)
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

func cloneItem(item Item) Item {
	item.Version.Content = append([]byte(nil), item.Version.Content...)
	item.Version.Meta = append([]byte(nil), item.Version.Meta...)
	item.Meta = cloneMetadata(item.Meta)
	return item
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.Xattr = make(map[string][]byte, len(metadata.Xattr))
	for key, value := range metadata.Xattr {
		metadata.Xattr[key] = append([]byte(nil), value...)
	}
	return metadata
}

func cloneChange(change Change) Change {
	if change.Item != nil {
		item := cloneItem(*change.Item)
		change.Item = &item
	}
	return change
}
