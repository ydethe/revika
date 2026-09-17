package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrNotFound    = errors.New("provider: item not found")
	ErrInvalidData = errors.New("provider: invalid data")
)

type ItemID string

const RootID ItemID = "root"

type Metadata struct {
	Mode          uint32
	UID           uint32
	GID           uint32
	ModTimeNS     int64
	ChangeTimeNS  int64
	AccessTimeNS  int64
	BirthTimeNS   int64
	Flags         uint32
	ContentType   string
	SymlinkTarget string
	Xattr         map[string][]byte
}

type Capabilities uint32

const (
	CapRead Capabilities = 1 << iota
	CapWrite
	CapRename
	CapReparent
	CapDelete
	CapAddSubItems
	CapEnumerate
)

func (caps Capabilities) Has(required Capabilities) bool {
	return caps&required == required
}

type ItemVersion struct {
	Content []byte
	Meta    []byte
}

type Item struct {
	ID      ItemID
	Parent  ItemID
	Name    string
	IsDir   bool
	IsLink  bool
	Size    int64
	Version ItemVersion
	Meta    Metadata
	Caps    Capabilities
}

type CreateRequest struct {
	Name     string
	IsDir    bool
	Meta     Metadata
	Contents io.Reader
}

type ModifyRequest struct {
	Contents io.Reader
	Meta     *Metadata
}

type ChangeType uint8

const (
	ChangeAdded ChangeType = iota
	ChangeModified
	ChangeDeleted
)

type Change struct {
	Type ChangeType
	ID   ItemID
	Path string
	Item *Item
}

type ChangeSet struct {
	Changes []Change
	Anchor  SyncAnchor
}

type SyncAnchor struct {
	Sequence uint64
	Root     []byte
}

func (anchor SyncAnchor) Bytes() []byte {
	result := make([]byte, 0, 4+8+4+len(anchor.Root))
	result = append(result, []byte("rvk-anchor-v1")...)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], anchor.Sequence)
	result = append(result, number[:]...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(anchor.Root)))
	result = append(result, length[:]...)
	return append(result, anchor.Root...)
}

func ParseAnchor(data []byte) (SyncAnchor, error) {
	if len(data) < len("rvk-anchor-v1")+8+4 || !bytes.Equal(data[:len("rvk-anchor-v1")], []byte("rvk-anchor-v1")) {
		return SyncAnchor{}, ErrInvalidData
	}
	position := len("rvk-anchor-v1")
	sequence := binary.BigEndian.Uint64(data[position : position+8])
	position += 8
	length := binary.BigEndian.Uint32(data[position : position+4])
	position += 4
	if uint64(length) > uint64(len(data)-position) || int(length) != len(data)-position {
		return SyncAnchor{}, ErrInvalidData
	}
	return SyncAnchor{Sequence: sequence, Root: append([]byte(nil), data[position:]...)}, nil
}

type Provider interface {
	Root(ctx context.Context) (ItemID, error)
	Stat(ctx context.Context, id ItemID) (Item, error)
	Lookup(ctx context.Context, parent ItemID, name string) (Item, error)
	Enumerate(ctx context.Context, directory ItemID) ([]Item, error)
	CurrentAnchor(ctx context.Context) (SyncAnchor, error)
	EnumerateChanges(ctx context.Context, since SyncAnchor) (ChangeSet, error)
	FetchContents(ctx context.Context, id ItemID, destination io.Writer) (ItemVersion, error)
	Evict(ctx context.Context, id ItemID) error
	CreateItem(ctx context.Context, parent ItemID, request CreateRequest) (Item, error)
	ModifyItem(ctx context.Context, id ItemID, request ModifyRequest) (Item, error)
	DeleteItem(ctx context.Context, id ItemID) error
	Rename(ctx context.Context, id ItemID, newParent ItemID, newName string) (Item, error)
}
