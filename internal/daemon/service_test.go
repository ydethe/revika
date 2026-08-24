package daemon

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/revika/revika/pkg/model"
)

func TestNewService_Success(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	defer svc.Stop()

	if svc.backend == nil {
		t.Errorf("expected non-nil backend")
	}
	if svc.ledger == nil {
		t.Errorf("expected non-nil ledger")
	}
}

func TestService_GetPeerID(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	defer svc.Stop()

	// Without a live daemon GetPeerID returns ""; this only asserts it never panics.
	_ = svc.GetPeerID()
}

func TestService_HandleIPCRequest_Connect(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	defer svc.Stop()

	params := model.ConnectParams{NetworkType: "Public"}
	paramsJSON, _ := json.Marshal(params)

	req := &model.IPCRequest{
		Method: "connect",
		Params: paramsJSON,
		ID:     1,
	}

	resp, err := svc.HandleIPCRequest(req)
	if err != nil {
		t.Fatalf("HandleIPCRequest failed: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("expected no error, got: %v", resp.Error)
	}

	if len(resp.Result) == 0 {
		t.Errorf("expected non-empty result")
	}
}

func TestService_HandleIPCRequest_MethodNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	defer svc.Stop()

	req := &model.IPCRequest{
		Method: "unknown_method",
		ID:     1,
	}

	resp, err := svc.HandleIPCRequest(req)
	if err != nil {
		t.Fatalf("HandleIPCRequest failed: %v", err)
	}

	if resp.Error == nil {
		t.Errorf("expected error for unknown method")
	}

	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestService_HandleIPCRequest_InvalidParams(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	defer svc.Stop()

	req := &model.IPCRequest{
		Method: "ls",
		Params: json.RawMessage(`{invalid json}`),
		ID:     1,
	}

	resp, err := svc.HandleIPCRequest(req)
	if err != nil {
		t.Fatalf("HandleIPCRequest failed: %v", err)
	}

	if resp.Error == nil {
		t.Errorf("expected error for invalid params")
	}

	if resp.Error.Code != -32602 {
		t.Errorf("expected error code -32602, got %d", resp.Error.Code)
	}
}

func TestService_HandleIPCRequest_Commands(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	defer svc.Stop()

	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{"ls", "ls", model.LsParams{Path: "/"}},
		{"cd", "cd", model.CdParams{Path: "/data"}},
		{"pwd", "pwd", nil},
		{"cp", "cp", model.CpParams{Src: "/a", Dst: "/b"}},
		{"rm", "rm", model.RmParams{Path: "/a"}},
		{"share", "share", model.ShareParams{FilePath: "/a", RecipientPeerID: "Qm123"}},
		{"revoke", "revoke", model.RevokeParams{FilePath: "/a", RecipientPeerID: "Qm123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var paramsJSON json.RawMessage
			if tt.params != nil {
				p, _ := json.Marshal(tt.params)
				paramsJSON = p
			}

			req := &model.IPCRequest{
				Method: tt.method,
				Params: paramsJSON,
				ID:     1,
			}

			resp, err := svc.HandleIPCRequest(req)
			if err != nil {
				t.Fatalf("HandleIPCRequest failed: %v", err)
			}

			if resp.Error != nil {
				t.Errorf("expected no error, got: %v", resp.Error)
			}

			if len(resp.Result) == 0 && tt.method != "pwd" {
				t.Errorf("expected non-empty result")
			}
		})
	}
}

func TestService_Start_Stop(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestService_Multiple_Instances(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath1 := filepath.Join(tmpDir, "ledger1.json")
	ipcAddr1 := filepath.Join(tmpDir, "daemon1.sock")

	ledgerPath2 := filepath.Join(tmpDir, "ledger2.json")
	ipcAddr2 := filepath.Join(tmpDir, "daemon2.sock")

	svc1, err := NewService(ledgerPath1, "127.0.0.1:5001", ipcAddr1)
	if err != nil {
		t.Fatalf("NewService 1 failed: %v", err)
	}
	defer svc1.Stop()

	svc2, err := NewService(ledgerPath2, "127.0.0.1:5001", ipcAddr2)
	if err != nil {
		t.Fatalf("NewService 2 failed: %v", err)
	}
	defer svc2.Stop()
}

// TestService_PersistentConnection sends two sequential requests on the SAME
// connection, guarding against the one-request-per-connection regression that
// caused a "broken pipe" on the second command.
func TestService_PersistentConnection(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer svc.Stop()

	conn, err := net.Dial("unix", ipcAddr)
	if err != nil {
		t.Fatalf("failed to dial daemon: %v", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	methods := []string{"pwd", "ls"}
	for i, method := range methods {
		id := i + 1

		var paramsJSON json.RawMessage
		if method == "ls" {
			p, _ := json.Marshal(model.LsParams{Path: "/"})
			paramsJSON = p
		}

		req := &model.IPCRequest{Method: method, Params: paramsJSON, ID: id}
		if err := encoder.Encode(req); err != nil {
			t.Fatalf("request %d (%s): encode failed: %v", id, method, err)
		}

		var resp model.IPCResponse
		if err := decoder.Decode(&resp); err != nil {
			t.Fatalf("request %d (%s): decode failed: %v", id, method, err)
		}

		if resp.Error != nil {
			t.Fatalf("request %d (%s): unexpected error: %v", id, method, resp.Error)
		}
		if resp.ID != id {
			t.Errorf("request %d (%s): expected response ID %d, got %d", id, method, id, resp.ID)
		}
		if len(resp.Result) == 0 {
			t.Errorf("request %d (%s): expected non-empty result", id, method)
		}
	}
}

// TestService_Stop_ClosesOpenConnection verifies Stop returns promptly with a
// connection open and a handler goroutine parked on Decode, and that the
// connection is force-closed (no goroutine leak).
func TestService_Stop_ClosesOpenConnection(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	ipcAddr := filepath.Join(tmpDir, "daemon.sock")

	svc, err := NewService(ledgerPath, "127.0.0.1:5001", ipcAddr)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	conn, err := net.Dial("unix", ipcAddr)
	if err != nil {
		t.Fatalf("failed to dial daemon: %v", err)
	}
	defer conn.Close()

	// Issue one request so the handler goroutine is established and then parks
	// on Decode awaiting the next request.
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	if err := encoder.Encode(&model.IPCRequest{Method: "pwd", ID: 1}); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	var resp model.IPCResponse
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Stop must return promptly, waiting for the parked handler to unwind.
	done := make(chan error, 1)
	go func() { done <- svc.Stop() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return promptly; handler goroutine likely leaked")
	}

	// The daemon closed its side; a read must now fail rather than block.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("expected read to fail after Stop closed the connection")
	}
}
