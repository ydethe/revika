package netframe

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := frame{opcode: opPut, requestID: 0x0102030405060708, payload: []byte("opaque ciphertext")}
	var buffer bytes.Buffer
	if err := writeFrame(&buffer, want); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got, err := readFrame(&buffer)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.opcode != want.opcode || got.requestID != want.requestID || !bytes.Equal(got.payload, want.payload) {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
	if buffer.Len() != 0 {
		t.Fatalf("expected buffer fully consumed, %d bytes left", buffer.Len())
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	var buffer bytes.Buffer
	if err := writeFrame(&buffer, frame{opcode: opEnd, requestID: 7}); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got, err := readFrame(&buffer)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.opcode != opEnd || got.requestID != 7 || len(got.payload) != 0 {
		t.Fatalf("unexpected frame %+v", got)
	}
}

func TestReadFrameBadMagic(t *testing.T) {
	corrupt := append([]byte("rvk-plugin-v9"), make([]byte, 13)...)
	_, err := readFrame(bytes.NewReader(corrupt))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol, got %v", err)
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	var buffer bytes.Buffer
	writeFrame(&buffer, frame{opcode: opGet, requestID: 1, payload: []byte("x")})
	truncated := buffer.Bytes()[:len(magicVersion)+2]
	_, err := readFrame(bytes.NewReader(truncated))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	var buffer bytes.Buffer
	writeFrame(&buffer, frame{opcode: opGet, requestID: 1, payload: []byte("payload")})
	full := buffer.Bytes()
	_, err := readFrame(bytes.NewReader(full[:len(full)-3]))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadFrameEmptyIsEOF(t *testing.T) {
	_, err := readFrame(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestWriteFrameOversizePayload(t *testing.T) {
	var buffer bytes.Buffer
	err := writeFrame(&buffer, frame{opcode: opData, payload: make([]byte, maxPayload+1)})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol, got %v", err)
	}
}

func TestReadFrameTrailingBytesLeftIntact(t *testing.T) {
	var buffer bytes.Buffer
	writeFrame(&buffer, frame{opcode: opHas, requestID: 3, payload: []byte("a")})
	writeFrame(&buffer, frame{opcode: opEnd, requestID: 3})
	first, err := readFrame(&buffer)
	if err != nil {
		t.Fatalf("first readFrame: %v", err)
	}
	if first.opcode != opHas {
		t.Fatalf("expected opHas first, got %v", first.opcode)
	}
	second, err := readFrame(&buffer)
	if err != nil {
		t.Fatalf("second readFrame: %v", err)
	}
	if second.opcode != opEnd {
		t.Fatalf("expected opEnd second, got %v", second.opcode)
	}
}
