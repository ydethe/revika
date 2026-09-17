package rootstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/revika/revika/internal/crypto"
)

var (
	ErrRollback    = errors.New("rootstore: root sequence does not advance")
	ErrInvalidRoot = errors.New("rootstore: invalid root pointer")
)

type RootPointer struct {
	Owner     []byte
	Sequence  uint64
	Timestamp int64
	Root      []byte
	Signature []byte
}

type Store interface {
	Load(ctx context.Context) (RootPointer, bool, error)
	Save(ctx context.Context, pointer RootPointer) error
}

func NewPointer(signer crypto.Signer, sequence uint64, timestamp int64, root []byte) (RootPointer, error) {
	pointer := RootPointer{
		Owner:     signer.Public(),
		Sequence:  sequence,
		Timestamp: timestamp,
		Root:      append([]byte(nil), root...),
	}
	signature, err := signer.Sign(pointer.SigningBytes())
	if err != nil {
		return RootPointer{}, err
	}
	pointer.Signature = signature
	return pointer, nil
}

func (pointer RootPointer) SigningBytes() []byte {
	return marshalFields(pointer.Owner, pointer.Sequence, pointer.Timestamp, pointer.Root)
}

func (pointer RootPointer) MarshalBinary() ([]byte, error) {
	if err := validateShape(pointer); err != nil {
		return nil, err
	}
	payload := pointer.SigningBytes()
	result := make([]byte, 0, len(payload)+4+len(pointer.Signature))
	result = append(result, payload...)
	result = appendBytes(result, pointer.Signature)
	return result, nil
}

func UnmarshalBinary(data []byte) (RootPointer, error) {
	reader := binaryReader{data: data}
	magic, err := reader.bytes()
	if err != nil || string(magic) != "revika-root-v1" {
		return RootPointer{}, ErrInvalidRoot
	}
	owner, err := reader.bytes()
	if err != nil {
		return RootPointer{}, ErrInvalidRoot
	}
	sequence, err := reader.uint64()
	if err != nil {
		return RootPointer{}, ErrInvalidRoot
	}
	timestamp, err := reader.int64()
	if err != nil {
		return RootPointer{}, ErrInvalidRoot
	}
	root, err := reader.bytes()
	if err != nil {
		return RootPointer{}, ErrInvalidRoot
	}
	signature, err := reader.bytes()
	if err != nil || reader.remaining() != 0 {
		return RootPointer{}, ErrInvalidRoot
	}
	pointer := RootPointer{Owner: owner, Sequence: sequence, Timestamp: timestamp, Root: root, Signature: signature}
	if err := validateShape(pointer); err != nil {
		return RootPointer{}, err
	}
	return pointer, nil
}

func Validate(pointer RootPointer, owner []byte) error {
	if err := validateShape(pointer); err != nil {
		return err
	}
	if !bytes.Equal(pointer.Owner, owner) {
		return ErrInvalidRoot
	}
	if err := crypto.VerifyEd25519(pointer.Owner, pointer.SigningBytes(), pointer.Signature); err != nil {
		return ErrInvalidRoot
	}
	return nil
}

type Memory struct {
	mu    sync.RWMutex
	owner []byte
	root  RootPointer
	ok    bool
}

func NewMemory(owner []byte) *Memory {
	return &Memory{owner: append([]byte(nil), owner...)}
}

func (s *Memory) Load(ctx context.Context) (RootPointer, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RootPointer{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ok {
		return RootPointer{}, false, nil
	}
	return clone(s.root), true, nil
}

func (s *Memory) Save(ctx context.Context, pointer RootPointer) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := Validate(pointer, s.owner); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ok && pointer.Sequence <= s.root.Sequence {
		return ErrRollback
	}
	s.root = clone(pointer)
	s.ok = true
	return nil
}

type File struct {
	path  string
	owner []byte
	mu    sync.Mutex
}

func NewFile(path string, owner []byte) *File {
	return &File{path: path, owner: append([]byte(nil), owner...)}
}

func (s *File) Load(ctx context.Context) (RootPointer, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RootPointer{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return RootPointer{}, false, nil
	}
	if err != nil {
		return RootPointer{}, false, fmt.Errorf("read root pointer: %w", err)
	}
	pointer, err := UnmarshalBinary(data)
	if err != nil {
		return RootPointer{}, false, err
	}
	if err := Validate(pointer, s.owner); err != nil {
		return RootPointer{}, false, err
	}
	return pointer, true, nil
}

func (s *File) Save(ctx context.Context, pointer RootPointer) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := Validate(pointer, s.owner); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok, err := s.loadLocked()
	if err != nil {
		return err
	}
	if ok && pointer.Sequence <= current.Sequence {
		return ErrRollback
	}
	data, err := pointer.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create root directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".root-*")
	if err != nil {
		return fmt.Errorf("create temporary root: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary root: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary root: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary root: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("commit root pointer: %w", err)
	}
	return nil
}

func (s *File) loadLocked() (RootPointer, bool, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return RootPointer{}, false, nil
	}
	if err != nil {
		return RootPointer{}, false, fmt.Errorf("read root pointer: %w", err)
	}
	pointer, err := UnmarshalBinary(data)
	if err != nil {
		return RootPointer{}, false, err
	}
	if err := Validate(pointer, s.owner); err != nil {
		return RootPointer{}, false, err
	}
	return pointer, true, nil
}

func validateShape(pointer RootPointer) error {
	if len(pointer.Owner) == 0 || len(pointer.Root) == 0 || len(pointer.Signature) == 0 {
		return ErrInvalidRoot
	}
	return nil
}

func marshalFields(owner []byte, sequence uint64, timestamp int64, root []byte) []byte {
	result := appendBytes(nil, []byte("revika-root-v1"))
	result = appendBytes(result, owner)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], sequence)
	result = append(result, number[:]...)
	binary.BigEndian.PutUint64(number[:], uint64(timestamp))
	result = append(result, number[:]...)
	return appendBytes(result, root)
}

func appendBytes(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func clone(pointer RootPointer) RootPointer {
	pointer.Owner = append([]byte(nil), pointer.Owner...)
	pointer.Root = append([]byte(nil), pointer.Root...)
	pointer.Signature = append([]byte(nil), pointer.Signature...)
	return pointer
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

type binaryReader struct {
	data []byte
	pos  int
}

func (r *binaryReader) bytes() ([]byte, error) {
	length, err := r.uint32()
	if err != nil || length > uint32(r.remaining()) {
		return nil, ErrInvalidRoot
	}
	value := append([]byte(nil), r.data[r.pos:r.pos+int(length)]...)
	r.pos += int(length)
	return value, nil
}

func (r *binaryReader) uint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, ErrInvalidRoot
	}
	value := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return value, nil
}

func (r *binaryReader) uint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, ErrInvalidRoot
	}
	value := binary.BigEndian.Uint64(r.data[r.pos : r.pos+8])
	r.pos += 8
	return value, nil
}

func (r *binaryReader) int64() (int64, error) {
	value, err := r.uint64()
	return int64(value), err
}

func (r *binaryReader) remaining() int { return len(r.data) - r.pos }
