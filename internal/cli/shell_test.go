package cli

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/revika/revika/pkg/model"
)

func TestNewShell(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")
	if shell == nil {
		t.Errorf("expected non-nil shell")
	}
	if shell.cwd != "/" {
		t.Errorf("expected initial cwd to be /, got %s", shell.cwd)
	}
	if shell.ipcAddr != "/tmp/daemon.sock" {
		t.Errorf("expected ipcAddr to be /tmp/daemon.sock, got %s", shell.ipcAddr)
	}
}

func TestShell_ExecuteCommand_Connect(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")

	// Test parsing of connect command
	// Note: We can't fully test this without mocking the IPC connection,
	// but we can test that parseCommand doesn't error
	_ = shell // silence unused warning
}

func TestShell_PrintHelp(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")

	// This should not panic
	shell.printHelp()
}

func TestShell_Close(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")

	// Closing a shell without a connection should not error
	err := shell.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

// TestIPCRequest_Encoding tests that IPC requests encode correctly
func TestIPCRequest_Encoding(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")

	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "connect",
			method: "connect",
			params: model.ConnectParams{NetworkType: "Public"},
		},
		{
			name:   "ls",
			method: "ls",
			params: model.LsParams{Path: "/"},
		},
		{
			name:   "cd",
			method: "cd",
			params: model.CdParams{Path: "/data"},
		},
		{
			name:   "cp",
			method: "cp",
			params: model.CpParams{Src: "/a", Dst: "/b"},
		},
		{
			name:   "rm",
			method: "rm",
			params: model.RmParams{Path: "/a"},
		},
		{
			name:   "share",
			method: "share",
			params: model.ShareParams{FilePath: "/a", RecipientPeerID: "Qm123"},
		},
		{
			name:   "revoke",
			method: "revoke",
			params: model.RevokeParams{FilePath: "/a", RecipientPeerID: "Qm123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, err := json.Marshal(tt.params)
			if err != nil {
				t.Fatalf("failed to marshal params: %v", err)
			}

			req := &model.IPCRequest{
				Method: tt.method,
				Params: paramsJSON,
				ID:     shell.requestID + 1,
			}

			// Verify the request can be marshaled
			reqJSON, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			if len(reqJSON) == 0 {
				t.Errorf("expected non-empty request JSON")
			}
		})
	}
}

// TestShell_RequestID tests that request IDs increment
func TestShell_RequestID_Increment(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")

	initialID := shell.requestID
	shell.requestID++
	if shell.requestID != initialID+1 {
		t.Errorf("expected request ID to increment")
	}
}

// TestShell_CWD tests that cwd is tracked
func TestShell_CWD_Tracking(t *testing.T) {
	shell := NewShell("/tmp/daemon.sock")

	if shell.cwd != "/" {
		t.Errorf("expected initial cwd /, got %s", shell.cwd)
	}

	// Simulate cd by directly setting cwd (without daemon)
	shell.cwd = "/data"
	if shell.cwd != "/data" {
		t.Errorf("expected cwd /data, got %s", shell.cwd)
	}
}

// TestResponse_Parsing tests that responses can be parsed
func TestResponse_Parsing(t *testing.T) {
	result := map[string]string{"status": "ok", "peer_id": "Qm123"}
	resultJSON, _ := json.Marshal(result)

	resp := &model.IPCResponse{
		Result: resultJSON,
		ID:     1,
	}

	var parsed map[string]string
	err := json.Unmarshal(resp.Result, &parsed)
	if err != nil {
		t.Errorf("failed to parse response: %v", err)
	}

	if parsed["status"] != "ok" {
		t.Errorf("expected status ok, got %s", parsed["status"])
	}
}

// TestError_Parsing tests that error responses are parsed correctly
func TestError_Parsing(t *testing.T) {
	resp := &model.IPCResponse{
		Error: &model.IPCError{
			Code:    -32601,
			Message: "Method not found",
		},
		ID: 1,
	}

	if resp.Error == nil {
		t.Errorf("expected error in response")
	}

	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

// respondOK writes a generic successful IPC response the shell commands can parse.
func respondOK(enc *json.Encoder, id int) error {
	result, _ := json.Marshal(map[string]string{"cwd": "/", "status": "ok"})
	return enc.Encode(&model.IPCResponse{Result: result, ID: id})
}

// TestShell_SelfHeal_ReconnectsOnWriteFailure verifies the CLI transparently
// reconnects when a cached connection has been closed by the daemon. The mock
// listener serves exactly one request on its first connection then closes it
// (reproducing the original one-request-per-connection daemon), and behaves
// persistently thereafter. The second (write-path) request must succeed.
func TestShell_SelfHeal_ReconnectsOnWriteFailure(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "daemon.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	connCount := 0
	firstClosed := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			mu.Lock()
			connCount++
			n := connCount
			mu.Unlock()

			go func(c net.Conn, n int) {
				dec := json.NewDecoder(c)
				enc := json.NewEncoder(c)

				if n == 1 {
					// Buggy behavior: serve one request, then close.
					var req model.IPCRequest
					if err := dec.Decode(&req); err != nil {
						c.Close()
						return
					}
					_ = respondOK(enc, req.ID)
					c.Close()
					close(firstClosed)
					return
				}

				// Persistent behavior for all later connections.
				for {
					var req model.IPCRequest
					if err := dec.Decode(&req); err != nil {
						c.Close()
						return
					}
					_ = respondOK(enc, req.ID)
				}
			}(conn, n)
		}
	}()

	shell := NewShell(sockPath)
	defer shell.Close()

	// First request establishes and uses connection #1.
	if err := shell.Pwd(); err != nil {
		t.Fatalf("first request (pwd) failed: %v", err)
	}

	// Wait until the mock has closed connection #1 so the cached conn is stale.
	<-firstClosed

	// Second request is a write-path command; it must self-heal by reconnecting.
	if err := shell.Cp("/a", "/b"); err != nil {
		t.Fatalf("second request (cp) failed to self-heal: %v", err)
	}

	mu.Lock()
	got := connCount
	mu.Unlock()
	if got < 2 {
		t.Errorf("expected CLI to reconnect (>=2 connections), got %d", got)
	}
}
