package manifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/revika/revika/internal/store"
)

const FormatVersion uint8 = 1

var ErrInvalidNode = errors.New("manifest: invalid node")

type Kind string

const (
	KindDirectory Kind = "directory"
	KindFile      Kind = "file"
	KindSymlink   Kind = "symlink"
)

type Reference struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	Size int64  `json:"size"`
}

type Node struct {
	Version  uint8                `json:"version"`
	Kind     Kind                 `json:"kind"`
	Metadata []byte               `json:"metadata,omitempty"`
	Content  []byte               `json:"content,omitempty"`
	Children map[string]Reference `json:"children,omitempty"`
}

func NewDirectory(metadata []byte, children map[string]Reference) Node {
	return Node{Version: FormatVersion, Kind: KindDirectory, Metadata: append([]byte(nil), metadata...), Children: cloneChildren(children)}
}

func NewFile(metadata, content []byte) Node {
	return Node{Version: FormatVersion, Kind: KindFile, Metadata: append([]byte(nil), metadata...), Content: append([]byte(nil), content...)}
}

func NewSymlink(metadata, target []byte) Node {
	return Node{Version: FormatVersion, Kind: KindSymlink, Metadata: append([]byte(nil), metadata...), Content: append([]byte(nil), target...)}
}

func (node Node) Validate() error {
	if node.Version != FormatVersion {
		return ErrInvalidNode
	}
	switch node.Kind {
	case KindDirectory:
		if node.Content != nil {
			return ErrInvalidNode
		}
		for name, reference := range node.Children {
			if name == "" || name == "." || name == ".." || reference.ID == "" {
				return ErrInvalidNode
			}
			if reference.Kind != KindDirectory && reference.Kind != KindFile && reference.Kind != KindSymlink {
				return ErrInvalidNode
			}
			if reference.Size < 0 {
				return ErrInvalidNode
			}
		}
	case KindFile, KindSymlink:
		if node.Children != nil {
			return ErrInvalidNode
		}
	default:
		return ErrInvalidNode
	}
	return nil
}

func (node Node) Encode() ([]byte, error) {
	if err := node.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(node)
}

func Decode(data []byte) (Node, error) {
	var node Node
	if err := json.Unmarshal(data, &node); err != nil {
		return Node{}, fmt.Errorf("manifest: decode node: %w", err)
	}
	if err := node.Validate(); err != nil {
		return Node{}, err
	}
	return node, nil
}

func ID(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (node Node) Address() (string, error) {
	encoded, err := node.Encode()
	if err != nil {
		return "", err
	}
	return ID(encoded), nil
}

func Save(ctx context.Context, objects store.Store, node Node) (string, error) {
	encoded, err := node.Encode()
	if err != nil {
		return "", err
	}
	address := ID(encoded)
	if err := objects.Put(ctx, store.ObjectID(address), bytes.NewReader(encoded)); err != nil && !errors.Is(err, store.ErrAlreadyExists) {
		return "", err
	}
	return address, nil
}

func Load(ctx context.Context, objects store.Store, address string) (Node, error) {
	reader, err := objects.Get(ctx, store.ObjectID(address))
	if errors.Is(err, store.ErrNotFound) {
		return Node{}, ErrInvalidNode
	}
	if err != nil {
		return Node{}, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(reader)
	if err != nil {
		return Node{}, err
	}
	if ID(encoded) != address {
		return Node{}, ErrInvalidNode
	}
	return Decode(encoded)
}

func cloneChildren(children map[string]Reference) map[string]Reference {
	if children == nil {
		return nil
	}
	result := make(map[string]Reference, len(children))
	for name, reference := range children {
		result[name] = reference
	}
	return result
}
