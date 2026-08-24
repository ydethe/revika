package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/revika/revika/internal/ipfs"
	"github.com/revika/revika/internal/ipfs/kubo"
	"github.com/revika/revika/internal/ledger"
	"github.com/revika/revika/pkg/model"
)

// Service is the User Daemon service that manages IPC and network connectivity.
type Service struct {
	backend    ipfs.Backend
	ledger     *ledger.Ledger
	ctx        context.Context
	cancel     context.CancelFunc
	ipcAddr    string // Unix socket or named pipe path
	ipcServer  net.Listener
	ledgerPath string

	connMu sync.Mutex
	conns  map[net.Conn]struct{} // live IPC connections, closed on Stop
	wg     sync.WaitGroup        // tracks in-flight connection handlers
}

// NewService creates a new User Daemon service backed by a Kubo IPFS adapter.
// apiAddr is the Kubo RPC API address (e.g. "127.0.0.1:5001"). Adapter
// construction is lazy, so a service can be created without a running daemon.
// Returns model.ErrNetworkFailure if initialization fails.
func NewService(ledgerPath string, apiAddr string, ipcAddr string) (*Service, error) {
	// Create context for lifecycle
	ctx, cancel := context.WithCancel(context.Background())

	// Load ledger (or create empty)
	daemonledger, err := ledger.Load(ledgerPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load ledger: %w", err)
	}

	// Create the Kubo IPFS backend (lazy: no daemon contact yet)
	backend, err := kubo.NewAdapter(apiAddr)
	if err != nil {
		cancel()
		return nil, err
	}

	return &Service{
		backend:    backend,
		ledger:     daemonledger,
		ctx:        ctx,
		cancel:     cancel,
		ipcAddr:    ipcAddr,
		ledgerPath: ledgerPath,
		conns:      make(map[net.Conn]struct{}),
	}, nil
}

// Start starts the daemon by listening for IPC connections.
func (s *Service) Start() error {
	log.Printf("Starting User Daemon (peer ID: %s)", s.GetPeerID())

	// Remove the socket file if it exists
	os.Remove(s.ipcAddr)

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.ipcAddr)
	if err != nil {
		return fmt.Errorf("failed to create IPC listener: %w", err)
	}

	s.ipcServer = listener

	// Start accepting connections in a goroutine
	go s.acceptConnections()

	log.Printf("User Daemon listening on %s", s.ipcAddr)
	return nil
}

// acceptConnections accepts and handles incoming IPC connections.
func (s *Service) acceptConnections() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.ipcServer.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("failed to accept IPC connection: %v", err)
			}
			continue
		}

		// Reject new connections once shutdown has begun.
		if !s.registerConn(conn) {
			conn.Close()
			continue
		}

		// Handle connection in a goroutine
		go s.handleIPCConnection(conn)
	}
}

// handleIPCConnection serves sequential requests on a single IPC connection
// until the client disconnects or the service is stopped.
func (s *Service) handleIPCConnection(conn net.Conn) {
	defer s.wg.Done()
	defer s.deregisterConn(conn)
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req model.IPCRequest
		if err := decoder.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				// Client hung up cleanly; not an error.
				return
			}
			log.Printf("failed to decode IPC request: %v", err)
			return
		}

		resp, err := s.HandleIPCRequest(&req)
		if err != nil {
			resp = &model.IPCResponse{
				Error: &model.IPCError{
					Code:    -1,
					Message: err.Error(),
				},
				ID: req.ID,
			}
		}

		if err := encoder.Encode(resp); err != nil {
			log.Printf("failed to encode IPC response: %v", err)
			return
		}
	}
}

// registerConn tracks a live connection so Stop can force it closed.
// It returns false if the service is already shutting down. The WaitGroup is
// incremented under the same lock Stop uses, so Add cannot race with Wait.
func (s *Service) registerConn(conn net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conns == nil {
		return false
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

// deregisterConn stops tracking a connection once its handler exits.
func (s *Service) deregisterConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conns != nil {
		delete(s.conns, conn)
	}
}

// HandleIPCRequest processes an incoming IPC request and returns a response.
func (s *Service) HandleIPCRequest(req *model.IPCRequest) (*model.IPCResponse, error) {
	switch req.Method {
	case "connect":
		return s.handleConnect(req)
	case "ls":
		return s.handleLs(req)
	case "cd":
		return s.handleCd(req)
	case "pwd":
		return s.handlePwd(req)
	case "cp":
		return s.handleCp(req)
	case "rm":
		return s.handleRm(req)
	case "share":
		return s.handleShare(req)
	case "revoke":
		return s.handleRevoke(req)
	default:
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32601,
				Message: "Method not found",
			},
			ID: req.ID,
		}, nil
	}
}

func (s *Service) handleConnect(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.ConnectParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would validate network type and establish connections
	result := map[string]string{"status": "connected", "peer_id": s.GetPeerID()}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handleLs(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.LsParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would list files at the given path
	result := map[string]interface{}{"path": params.Path, "files": []string{}}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handleCd(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.CdParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would change the working directory
	result := map[string]string{"cwd": params.Path}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handlePwd(req *model.IPCRequest) (*model.IPCResponse, error) {
	// In a full implementation, this would return the current working directory
	result := map[string]string{"cwd": "/"}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handleCp(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.CpParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would copy a file
	result := map[string]string{"status": "ok", "src": params.Src, "dst": params.Dst}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handleRm(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.RmParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would remove a file
	result := map[string]string{"status": "ok"}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handleShare(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.ShareParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would share a file
	result := map[string]string{"status": "ok"}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

func (s *Service) handleRevoke(req *model.IPCRequest) (*model.IPCResponse, error) {
	var params model.RevokeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &model.IPCResponse{
			Error: &model.IPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}, nil
	}

	// In a full implementation, this would revoke access
	result := map[string]string{"status": "ok"}
	resultJSON, _ := json.Marshal(result)

	return &model.IPCResponse{
		Result: resultJSON,
		ID:     req.ID,
	}, nil
}

// Stop gracefully shuts down the daemon.
func (s *Service) Stop() error {
	log.Printf("Stopping User Daemon")
	s.cancel()

	if s.ipcServer != nil {
		s.ipcServer.Close()
	}

	// Force-close live connections so any handler parked on Decode unblocks
	// and returns instead of leaking.
	s.connMu.Lock()
	conns := s.conns
	s.conns = nil
	s.connMu.Unlock()
	for conn := range conns {
		conn.Close()
	}
	s.wg.Wait()

	// Save ledger before shutdown
	if err := s.ledger.Save(s.ledgerPath); err != nil {
		log.Printf("failed to save ledger on shutdown: %v", err)
	}

	// Clean up IPC socket
	os.Remove(s.ipcAddr)

	return nil
}

// GetPeerID returns the IPFS peer ID of this daemon, or "" if unreachable.
func (s *Service) GetPeerID() string {
	id, err := s.backend.ID(context.Background())
	if err != nil {
		return ""
	}
	return id
}
