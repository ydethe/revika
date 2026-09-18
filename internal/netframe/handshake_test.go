package netframe

import (
	"bufio"
	"errors"
	"net"
	"testing"
)

// pipePair returns two ends of an in-memory connection wrapped in bufio, matching how the
// real code drives the handshake over a net.Conn.
func pipePair(t *testing.T) (clientReader *bufio.Reader, clientWriter *bufio.Writer, serverReader *bufio.Reader, serverWriter *bufio.Writer, closeAll func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	return bufio.NewReader(clientConn), bufio.NewWriter(clientConn),
		bufio.NewReader(serverConn), bufio.NewWriter(serverConn),
		func() { clientConn.Close(); serverConn.Close() }
}

func TestHandshakeSuccess(t *testing.T) {
	cr, cw, sr, sw, closeAll := pipePair(t)
	defer closeAll()
	secret := []byte("shared-secret")

	serverErr := make(chan error, 1)
	go func() { serverErr <- serverHandshake(sr, sw, secret) }()

	if err := clientHandshake(cr, cw, secret); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

func TestHandshakeWrongSecret(t *testing.T) {
	cr, cw, sr, sw, closeAll := pipePair(t)
	defer closeAll()

	serverErr := make(chan error, 1)
	go func() { serverErr <- serverHandshake(sr, sw, []byte("server-secret")) }()

	clientErr := clientHandshake(cr, cw, []byte("client-secret"))
	if !errors.Is(clientErr, ErrUnauthenticated) {
		t.Fatalf("expected client ErrUnauthenticated, got %v", clientErr)
	}
	if err := <-serverErr; !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected server ErrUnauthenticated, got %v", err)
	}
}
