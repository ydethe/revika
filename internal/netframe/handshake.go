package netframe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

const nonceSize = 16

// computeProof binds both nonces and a direction label under the shared secret. The label
// ("client"/"server") makes the two proofs distinct so one cannot be reflected as the other.
func computeProof(secret, first, second []byte, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(first)
	mac.Write(second)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// clientHandshake performs the mutual HMAC challenge-response from the dialing side.
// It authenticates both peers with a shared secret but does not encrypt the connection
// (envelope confidentiality is out of scope for this transport; see §4.5.1).
func clientHandshake(r io.Reader, w writeFlusher, secret []byte) error {
	clientNonce := make([]byte, nonceSize)
	if _, err := rand.Read(clientNonce); err != nil {
		return err
	}
	if err := writeFlush(w, frame{opcode: opHello, payload: clientNonce}); err != nil {
		return err
	}
	hello, err := readFrame(r)
	if err != nil {
		return err
	}
	if hello.opcode != opHello || len(hello.payload) != nonceSize {
		return ErrProtocol
	}
	serverNonce := hello.payload
	proof := computeProof(secret, serverNonce, clientNonce, "client")
	if err := writeFlush(w, frame{opcode: opAuth, payload: proof}); err != nil {
		return err
	}
	auth, err := readFrame(r)
	if err != nil {
		return err
	}
	if auth.opcode == opError {
		// During the handshake an ERROR frame can only mean the server rejected our proof.
		return ErrUnauthenticated
	}
	if auth.opcode != opAuth {
		return ErrProtocol
	}
	expected := computeProof(secret, clientNonce, serverNonce, "server")
	if !hmac.Equal(auth.payload, expected) {
		return ErrUnauthenticated
	}
	return nil
}

// serverHandshake performs the mutual HMAC challenge-response from the accepting side.
// It verifies the client's proof before revealing its own.
func serverHandshake(r io.Reader, w writeFlusher, secret []byte) error {
	hello, err := readFrame(r)
	if err != nil {
		return err
	}
	if hello.opcode != opHello || len(hello.payload) != nonceSize {
		return ErrProtocol
	}
	clientNonce := hello.payload
	serverNonce := make([]byte, nonceSize)
	if _, err := rand.Read(serverNonce); err != nil {
		return err
	}
	if err := writeFlush(w, frame{opcode: opHello, payload: serverNonce}); err != nil {
		return err
	}
	auth, err := readFrame(r)
	if err != nil {
		return err
	}
	if auth.opcode != opAuth {
		return ErrProtocol
	}
	expected := computeProof(secret, serverNonce, clientNonce, "client")
	if !hmac.Equal(auth.payload, expected) {
		_ = writeFlush(w, frame{opcode: opError, payload: encodeErrorPayload(ErrUnauthenticated)})
		return ErrUnauthenticated
	}
	proof := computeProof(secret, clientNonce, serverNonce, "server")
	return writeFlush(w, frame{opcode: opAuth, payload: proof})
}

func writeFlush(w writeFlusher, f frame) error {
	if err := writeFrame(w, f); err != nil {
		return err
	}
	return w.Flush()
}
