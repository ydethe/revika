package netframe

import (
	"errors"
	"fmt"

	"github.com/revika/revika/internal/store"
)

// ErrUnauthenticated reports that the shared-secret handshake failed.
var ErrUnauthenticated = errors.New("netframe: authentication failed")

// ErrUnsupported reports that the backend does not support the requested operation.
// It is the sentinel a backend returns for a load-bearing operation it cannot honour,
// so the caller can distinguish it from a false success (docs/Architecture.md §4.4).
var ErrUnsupported = errors.New("netframe: operation not supported")

// ErrTransient reports a temporary backend failure that may succeed on retry.
var ErrTransient = errors.New("netframe: transient failure")

// errorCode is the first byte of an opError payload; the remainder is a UTF-8 message.
type errorCode uint8

const (
	codeUnknown errorCode = iota
	codeNotFound
	codeAlreadyExists
	codeUnsupported
	codeTransient
	codePermanent
)

func encodeError(err error) errorCode {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return codeNotFound
	case errors.Is(err, store.ErrAlreadyExists):
		return codeAlreadyExists
	case errors.Is(err, ErrUnsupported):
		return codeUnsupported
	case errors.Is(err, ErrTransient):
		return codeTransient
	default:
		return codePermanent
	}
}

func encodeErrorPayload(err error) []byte {
	message := err.Error()
	payload := make([]byte, 0, 1+len(message))
	payload = append(payload, byte(encodeError(err)))
	return append(payload, message...)
}

// decodeErrorPayload maps an opError payload back to a sentinel where one exists, so a
// caller can errors.Is against store.ErrNotFound and the like across the boundary.
func decodeErrorPayload(payload []byte) error {
	if len(payload) == 0 {
		return ErrProtocol
	}
	message := string(payload[1:])
	switch errorCode(payload[0]) {
	case codeNotFound:
		return store.ErrNotFound
	case codeAlreadyExists:
		return store.ErrAlreadyExists
	case codeUnsupported:
		return ErrUnsupported
	case codeTransient:
		return ErrTransient
	default:
		if message == "" {
			return errors.New("netframe: remote error")
		}
		return fmt.Errorf("netframe: remote error: %s", message)
	}
}
