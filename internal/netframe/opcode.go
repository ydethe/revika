package netframe

// opcode identifies the kind of a frame. Values are stable on the wire; append new
// opcodes rather than renumbering.
type opcode uint8

const (
	opHello  opcode = iota + 1 // handshake: nonce exchange
	opAuth                     // handshake: HMAC proof exchange
	opPut                      // request: store an object (followed by DATA... END)
	opGet                      // request: fetch an object (response is DATA... END)
	opHas                      // request/response: existence probe
	opDelete                   // request: remove an object
	opClose                    // request: client is done; server ends the connection
	opData                     // stream: one chunk of an object body
	opEnd                      // terminator: end of a stream / success status
	opError                    // terminator: an error status carrying a code + message
)
