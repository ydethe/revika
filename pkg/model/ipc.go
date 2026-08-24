package model

import "encoding/json"

// JSON-RPC 2.0 request/response for CLI ↔ Daemon IPC

// IPCRequest represents a JSON-RPC 2.0 request from CLI to daemon.
type IPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
	ID     int             `json:"id"`
}

// IPCResponse represents a JSON-RPC 2.0 response from daemon to CLI.
type IPCResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *IPCError       `json:"error,omitempty"`
	ID     int             `json:"id"`
}

// IPCError represents a JSON-RPC 2.0 error response.
type IPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// CLI command parameter types

// ConnectParams are parameters for the "connect" IPC command.
type ConnectParams struct {
	NetworkType string `json:"network_type"` // "Public", "Hybrid", "Private"
}

// LsParams are parameters for the "ls" IPC command.
type LsParams struct {
	Path string `json:"path"`
}

// CdParams are parameters for the "cd" IPC command.
type CdParams struct {
	Path string `json:"path"`
}

// CpParams are parameters for the "cp" IPC command.
type CpParams struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// RmParams are parameters for the "rm" IPC command.
type RmParams struct {
	Path string `json:"path"`
}

// ShareParams are parameters for the "share" IPC command.
type ShareParams struct {
	FilePath        string `json:"file_path"`
	RecipientPeerID string `json:"recipient_peer_id"`
}

// RevokeParams are parameters for the "revoke" IPC command.
type RevokeParams struct {
	FilePath        string `json:"file_path"`
	RecipientPeerID string `json:"recipient_peer_id"`
}
