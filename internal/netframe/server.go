package netframe

import (
	"bufio"
	"context"
	"io"
	"net"

	"github.com/revika/revika/internal/store"
)

// Serve accepts connections on listener and answers store operations against backend,
// authenticating each connection with the shared secret. It runs until ctx is cancelled
// (which closes the listener) or Accept fails for another reason. Each connection is
// handled on its own goroutine; a per-connection error closes only that connection.
func Serve(ctx context.Context, listener net.Listener, backend store.Store, secret []byte) error {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go handleConn(ctx, conn, backend, secret)
	}
}

func handleConn(ctx context.Context, conn net.Conn, backend store.Store, secret []byte) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if err := serverHandshake(reader, writer, secret); err != nil {
		return
	}
	for {
		request, err := readFrame(reader)
		if err != nil {
			return
		}
		if err := dispatch(ctx, reader, writer, backend, request); err != nil {
			return
		}
	}
}

// dispatch handles one request. A returned error is a transport- or protocol-level fault
// that closes the connection; an application error (e.g. ErrNotFound) is reported to the
// client as an opError frame and returns nil so the connection stays open.
func dispatch(ctx context.Context, reader *bufio.Reader, writer *bufio.Writer, backend store.Store, request frame) error {
	switch request.opcode {
	case opPut:
		return handlePut(ctx, reader, writer, backend, request)
	case opGet:
		return handleGet(ctx, writer, backend, request)
	case opHas:
		return handleHas(ctx, writer, backend, request)
	case opDelete:
		return handleDelete(ctx, writer, backend, request)
	case opClose:
		return io.EOF
	default:
		return ErrProtocol
	}
}

func handlePut(ctx context.Context, reader *bufio.Reader, writer *bufio.Writer, backend store.Store, request frame) error {
	id := store.ObjectID(request.payload)
	pipeReader, pipeWriter := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := backend.Put(ctx, id, pipeReader)
		// If the backend returned without draining the body — e.g. an early
		// ErrAlreadyExists after an existence check, as ipfsstore does — close the read
		// end so a pending or subsequent pipeWriter.Write unblocks instead of deadlocking
		// the drain loop below.
		pipeReader.CloseWithError(err)
		done <- err
	}()

	// Drain DATA frames until END regardless of an early Put failure, so the connection
	// stays framed for the next request. Stop feeding the pipe once a write fails.
	var streamErr error
	for {
		chunk, err := readFrame(reader)
		if err != nil {
			pipeWriter.CloseWithError(err)
			<-done
			return err
		}
		if chunk.opcode == opEnd {
			break
		}
		if chunk.opcode != opData {
			pipeWriter.CloseWithError(ErrProtocol)
			<-done
			return ErrProtocol
		}
		if streamErr == nil {
			if _, err := pipeWriter.Write(chunk.payload); err != nil {
				streamErr = err
			}
		}
	}
	pipeWriter.Close()
	putErr := <-done
	if putErr == nil {
		putErr = streamErr
	}
	return respondStatus(writer, request.requestID, putErr)
}

func handleGet(ctx context.Context, writer *bufio.Writer, backend store.Store, request frame) error {
	id := store.ObjectID(request.payload)
	content, err := backend.Get(ctx, id)
	if err != nil {
		return respondStatus(writer, request.requestID, err)
	}
	defer content.Close()
	buffer := make([]byte, chunkSize)
	for {
		n, readErr := content.Read(buffer)
		if n > 0 {
			if err := writeFrame(writer, frame{opcode: opData, requestID: request.requestID, payload: buffer[:n]}); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			// Failure after some DATA was already sent: the client maps a trailing
			// opError to an error regardless of the bytes it buffered.
			if err := writeFrame(writer, frame{opcode: opError, requestID: request.requestID, payload: encodeErrorPayload(readErr)}); err != nil {
				return err
			}
			return writer.Flush()
		}
	}
	if err := writeFrame(writer, frame{opcode: opEnd, requestID: request.requestID}); err != nil {
		return err
	}
	return writer.Flush()
}

func handleHas(ctx context.Context, writer *bufio.Writer, backend store.Store, request frame) error {
	present, err := backend.Has(ctx, store.ObjectID(request.payload))
	if err != nil {
		return respondStatus(writer, request.requestID, err)
	}
	flag := byte(0)
	if present {
		flag = 1
	}
	if err := writeFrame(writer, frame{opcode: opHas, requestID: request.requestID, payload: []byte{flag}}); err != nil {
		return err
	}
	return writer.Flush()
}

func handleDelete(ctx context.Context, writer *bufio.Writer, backend store.Store, request frame) error {
	err := backend.Delete(ctx, store.ObjectID(request.payload))
	return respondStatus(writer, request.requestID, err)
}

func respondStatus(writer *bufio.Writer, requestID uint64, err error) error {
	response := frame{opcode: opEnd, requestID: requestID}
	if err != nil {
		response = frame{opcode: opError, requestID: requestID, payload: encodeErrorPayload(err)}
	}
	if writeErr := writeFrame(writer, response); writeErr != nil {
		return writeErr
	}
	return writer.Flush()
}
