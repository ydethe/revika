// Package netframe implements the revika out-of-process adapter wire protocol
// (docs/Architecture.md §4.5.1): size-prefixed binary frames carried over a TCP
// connection, with a shared-secret handshake, exposing a store.Store across the
// process boundary. Both the client (a store.Store that dials an adapter) and the
// server (Serve, which backs an adapter binary) live here so they share one codec.
package netframe

import (
	"encoding/binary"
	"errors"
	"io"
)

// magicVersion is written at the head of every frame so a reader can hard-fail on
// desync and the wire format can be versioned, matching the rvk-*-v1 discipline used
// elsewhere in the codebase (internal/rootstore, internal/provider).
const magicVersion = "rvk-plugin-v1"

const (
	// chunkSize bounds each streamed DATA frame so neither peer buffers an unbounded blob.
	chunkSize = 64 << 10
	// maxPayload guards a reader against a hostile or corrupt length prefix.
	maxPayload = 1 << 20
)

// ErrProtocol indicates a malformed, out-of-order, or unexpected frame on the wire.
var ErrProtocol = errors.New("netframe: protocol violation")

// writeFlusher is satisfied by *bufio.Writer; the handshake and server flush explicitly.
type writeFlusher interface {
	io.Writer
	Flush() error
}

type frame struct {
	opcode    opcode
	requestID uint64
	payload   []byte
}

// writeFrame serializes a frame. The header is written separately from the payload so a
// large payload is not copied into an intermediate buffer.
func writeFrame(w io.Writer, f frame) error {
	if len(f.payload) > maxPayload {
		return ErrProtocol
	}
	header := make([]byte, 0, len(magicVersion)+1+8+4)
	header = append(header, magicVersion...)
	header = append(header, byte(f.opcode))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], f.requestID)
	header = append(header, number[:]...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(f.payload)))
	header = append(header, length[:]...)
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(f.payload) > 0 {
		if _, err := w.Write(f.payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrame reads and validates one frame. A short read surfaces as io.EOF or
// io.ErrUnexpectedEOF (connection closed); any framing violation collapses to ErrProtocol.
func readFrame(r io.Reader) (frame, error) {
	magic := make([]byte, len(magicVersion))
	if _, err := io.ReadFull(r, magic); err != nil {
		return frame{}, err
	}
	if string(magic) != magicVersion {
		return frame{}, ErrProtocol
	}
	var head [1 + 8 + 4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return frame{}, err
	}
	f := frame{
		opcode:    opcode(head[0]),
		requestID: binary.BigEndian.Uint64(head[1:9]),
	}
	length := binary.BigEndian.Uint32(head[9:13])
	if length > maxPayload {
		return frame{}, ErrProtocol
	}
	if length > 0 {
		f.payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}
