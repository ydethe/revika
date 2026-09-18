package netframe

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/revika/revika/internal/store"
)

// Client is a store.Store that speaks the frame protocol to a remote adapter over TCP.
// Calls are serialized on a single connection: requestID is reserved for future
// multiplexing but v1 issues one request at a time under a mutex. Get responses are
// buffered in full before the mutex is released, so the connection is free for the next
// call; streaming a Get body end-to-end is a later enhancement.
type Client struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	nextID uint64
	closed bool
}

var _ store.Store = (*Client)(nil)

// Dial connects to a revika adapter at address and completes the shared-secret handshake.
func Dial(ctx context.Context, address string, secret []byte) (*Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	client := &Client{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}
	if err := clientHandshake(client.reader, client.writer, secret); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

func (c *Client) Put(ctx context.Context, id store.ObjectID, content io.Reader) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin(ctx); err != nil {
		return err
	}
	defer c.applyDeadline(ctx)()
	requestID := c.nextRequestID()
	if err := writeFrame(c.writer, frame{opcode: opPut, requestID: requestID, payload: []byte(id)}); err != nil {
		return c.transport(err)
	}
	buffer := make([]byte, chunkSize)
	for {
		n, readErr := content.Read(buffer)
		if n > 0 {
			if err := writeFrame(c.writer, frame{opcode: opData, requestID: requestID, payload: buffer[:n]}); err != nil {
				return c.transport(err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			// A source read failure leaves the server mid-object; drop the connection
			// rather than send a truncated END that would commit partial data.
			return c.transport(readErr)
		}
	}
	if err := writeFrame(c.writer, frame{opcode: opEnd, requestID: requestID}); err != nil {
		return c.transport(err)
	}
	if err := c.writer.Flush(); err != nil {
		return c.transport(err)
	}
	return c.readStatus(requestID)
}

func (c *Client) Get(ctx context.Context, id store.ObjectID) (io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin(ctx); err != nil {
		return nil, err
	}
	defer c.applyDeadline(ctx)()
	requestID := c.nextRequestID()
	if err := c.request(opGet, requestID, []byte(id)); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	for {
		response, err := readFrame(c.reader)
		if err != nil {
			return nil, c.transport(err)
		}
		if response.requestID != requestID {
			return nil, c.transport(ErrProtocol)
		}
		switch response.opcode {
		case opData:
			buffer.Write(response.payload)
		case opEnd:
			return io.NopCloser(bytes.NewReader(buffer.Bytes())), nil
		case opError:
			return nil, decodeErrorPayload(response.payload)
		default:
			return nil, c.transport(ErrProtocol)
		}
	}
}

func (c *Client) Has(ctx context.Context, id store.ObjectID) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin(ctx); err != nil {
		return false, err
	}
	defer c.applyDeadline(ctx)()
	requestID := c.nextRequestID()
	if err := c.request(opHas, requestID, []byte(id)); err != nil {
		return false, err
	}
	response, err := readFrame(c.reader)
	if err != nil {
		return false, c.transport(err)
	}
	if response.requestID != requestID {
		return false, c.transport(ErrProtocol)
	}
	switch response.opcode {
	case opHas:
		return len(response.payload) == 1 && response.payload[0] != 0, nil
	case opError:
		return false, decodeErrorPayload(response.payload)
	default:
		return false, c.transport(ErrProtocol)
	}
}

func (c *Client) Delete(ctx context.Context, id store.ObjectID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin(ctx); err != nil {
		return err
	}
	defer c.applyDeadline(ctx)()
	requestID := c.nextRequestID()
	if err := c.request(opDelete, requestID, []byte(id)); err != nil {
		return err
	}
	return c.readStatus(requestID)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	_ = writeFrame(c.writer, frame{opcode: opClose, requestID: c.nextRequestID()})
	_ = c.writer.Flush()
	c.closed = true
	return c.conn.Close()
}

// request writes a single request frame and flushes it.
func (c *Client) request(op opcode, requestID uint64, payload []byte) error {
	if err := writeFrame(c.writer, frame{opcode: op, requestID: requestID, payload: payload}); err != nil {
		return c.transport(err)
	}
	if err := c.writer.Flush(); err != nil {
		return c.transport(err)
	}
	return nil
}

// readStatus reads a single END/ERROR status response. Transport and protocol faults
// drop the connection; an application error (decoded from ERROR) leaves it open.
func (c *Client) readStatus(requestID uint64) error {
	response, err := readFrame(c.reader)
	if err != nil {
		return c.transport(err)
	}
	if response.requestID != requestID {
		return c.transport(ErrProtocol)
	}
	switch response.opcode {
	case opEnd:
		return nil
	case opError:
		return decodeErrorPayload(response.payload)
	default:
		return c.transport(ErrProtocol)
	}
}

// begin guards a call: it rejects a closed client and honours a cancelled context.
func (c *Client) begin(ctx context.Context) error {
	if c.closed {
		return net.ErrClosed
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

// applyDeadline maps a context deadline onto the connection and returns a reset func.
func (c *Client) applyDeadline(ctx context.Context) func() {
	if ctx == nil {
		return func() {}
	}
	if deadline, ok := ctx.Deadline(); ok {
		c.conn.SetDeadline(deadline)
		return func() { c.conn.SetDeadline(time.Time{}) }
	}
	return func() {}
}

// transport marks the connection unusable after a transport- or protocol-level fault so a
// desynced stream is never reused, then returns the triggering error.
func (c *Client) transport(err error) error {
	if !c.closed {
		c.closed = true
		c.conn.Close()
	}
	return err
}

func (c *Client) nextRequestID() uint64 {
	c.nextID++
	return c.nextID
}
