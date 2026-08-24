package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/revika/revika/pkg/model"
)

// Shell is the interactive CLI REPL for the user.
type Shell struct {
	ipcAddr   string
	cwd       string // current working directory
	conn      net.Conn
	encoder   *json.Encoder
	decoder   *json.Decoder
	requestID int
}

// NewShell creates an interactive CLI shell connected to a daemon at ipcAddr.
func NewShell(ipcAddr string) *Shell {
	return &Shell{
		ipcAddr:   ipcAddr,
		cwd:       "/",
		requestID: 0,
	}
}

// Run starts the interactive loop, reading from stdin.
// It sends commands to the daemon via IPC and prints results.
func (s *Shell) Run() error {
	reader := bufio.NewReader(os.Stdin)
	return s.RunWithReader(reader)
}

// RunWithReader starts the interactive loop with a custom reader.
// It reads commands, sends them to the daemon via IPC, and prints results.
func (s *Shell) RunWithReader(reader *bufio.Reader) error {
	fmt.Println("Revika CLI - Type 'help' for commands, 'exit' to quit")

	for {
		fmt.Print("revika> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println()
				break
			}
			fmt.Printf("error reading input: %v\n", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" {
			break
		}

		if line == "help" {
			s.printHelp()
			continue
		}

		if err := s.executeCommand(line); err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}

	return nil
}

// executeCommand parses and executes a command.
func (s *Shell) executeCommand(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	cmd := parts[0]

	switch cmd {
	case "connect":
		if len(parts) < 2 {
			return fmt.Errorf("usage: connect <network_type>")
		}
		return s.Connect(parts[1])

	case "cd":
		if len(parts) < 2 {
			return fmt.Errorf("usage: cd <path>")
		}
		return s.Cd(parts[1])

	case "pwd":
		return s.Pwd()

	case "ls":
		path := "."
		if len(parts) > 1 {
			path = parts[1]
		}
		return s.Ls(path)

	case "cp":
		if len(parts) < 3 {
			return fmt.Errorf("usage: cp <src> <dst>")
		}
		return s.Cp(parts[1], parts[2])

	case "rm":
		if len(parts) < 2 {
			return fmt.Errorf("usage: rm <path>")
		}
		return s.Rm(parts[1])

	case "share":
		if len(parts) < 3 {
			return fmt.Errorf("usage: share <file_path> <recipient_peer_id>")
		}
		return s.Share(parts[1], parts[2])

	case "revoke":
		if len(parts) < 3 {
			return fmt.Errorf("usage: revoke <file_path> <recipient_peer_id>")
		}
		return s.Revoke(parts[1], parts[2])

	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

// dial establishes a fresh IPC connection and its cached JSON codecs.
// The persistent connection reuses a single decoder so buffered bytes are
// never lost between requests.
func (s *Shell) dial() error {
	conn, err := net.Dial("unix", s.ipcAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	s.conn = conn
	s.encoder = json.NewEncoder(conn)
	s.decoder = json.NewDecoder(conn)
	return nil
}

// resetConn tears down the cached connection and codecs so the next request
// dials afresh.
func (s *Shell) resetConn() {
	if s.conn != nil {
		s.conn.Close()
	}
	s.conn = nil
	s.encoder = nil
	s.decoder = nil
}

// sendIPCRequest sends a request to the daemon and receives a response.
// The daemon serves multiple requests per connection, so the connection and
// its codecs are cached. A failed write (e.g. the daemon closed a stale
// connection) is retried once with a fresh dial. A failed read is never
// retried because the request may have already executed, and commands such as
// cp/rm/share/revoke are not idempotent.
func (s *Shell) sendIPCRequest(method string, params interface{}) (*model.IPCResponse, error) {
	s.requestID++

	paramsJSON, _ := json.Marshal(params)

	req := &model.IPCRequest{
		Method: method,
		Params: paramsJSON,
		ID:     s.requestID,
	}

	freshDial := s.conn == nil
	if freshDial {
		if err := s.dial(); err != nil {
			return nil, err
		}
	}

	// Send request, retrying once on write failure with a fresh connection.
	if err := s.encoder.Encode(req); err != nil {
		s.resetConn()
		if freshDial {
			// The connection was already fresh; a write failure is fatal.
			return nil, fmt.Errorf("failed to send IPC request: %w", err)
		}
		if err := s.dial(); err != nil {
			return nil, err
		}
		if err := s.encoder.Encode(req); err != nil {
			s.resetConn()
			return nil, fmt.Errorf("failed to send IPC request: %w", err)
		}
	}

	// Receive response. Never retry a read failure: the request may already
	// have been executed by the daemon.
	var resp model.IPCResponse
	if err := s.decoder.Decode(&resp); err != nil {
		s.resetConn()
		return nil, fmt.Errorf("failed to receive IPC response: %w", err)
	}

	return &resp, nil
}

// Connect connects to the network.
func (s *Shell) Connect(networkType string) error {
	params := model.ConnectParams{NetworkType: networkType}
	resp, err := s.sendIPCRequest("connect", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	var result map[string]string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("Connected: %s\n", result["status"])
	return nil
}

// Cd changes the working directory.
func (s *Shell) Cd(path string) error {
	params := model.CdParams{Path: path}
	resp, err := s.sendIPCRequest("cd", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	var result map[string]string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	s.cwd = result["cwd"]
	return nil
}

// Pwd prints the current working directory.
func (s *Shell) Pwd() error {
	resp, err := s.sendIPCRequest("pwd", nil)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	var result map[string]string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Println(result["cwd"])
	return nil
}

// Ls lists files at the given path.
func (s *Shell) Ls(path string) error {
	params := model.LsParams{Path: path}
	resp, err := s.sendIPCRequest("ls", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	files := result["files"].([]interface{})
	if len(files) == 0 {
		fmt.Println("(empty directory)")
		return nil
	}

	for _, file := range files {
		fmt.Println(file)
	}

	return nil
}

// Cp copies a file from src to dst.
func (s *Shell) Cp(src, dst string) error {
	params := model.CpParams{Src: src, Dst: dst}
	resp, err := s.sendIPCRequest("cp", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	var result map[string]string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("Copied: %s -> %s\n", src, dst)
	return nil
}

// Rm removes a file.
func (s *Shell) Rm(path string) error {
	params := model.RmParams{Path: path}
	resp, err := s.sendIPCRequest("rm", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	fmt.Printf("Removed: %s\n", path)
	return nil
}

// Share shares a file with another peer.
func (s *Shell) Share(filePath, recipientID string) error {
	params := model.ShareParams{FilePath: filePath, RecipientPeerID: recipientID}
	resp, err := s.sendIPCRequest("share", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	fmt.Printf("Shared: %s with %s\n", filePath, recipientID)
	return nil
}

// Revoke revokes access to a file.
func (s *Shell) Revoke(filePath, recipientID string) error {
	params := model.RevokeParams{FilePath: filePath, RecipientPeerID: recipientID}
	resp, err := s.sendIPCRequest("revoke", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("daemon error: %s", resp.Error.Message)
	}

	fmt.Printf("Revoked: access to %s from %s\n", filePath, recipientID)
	return nil
}

// printHelp prints available commands.
func (s *Shell) printHelp() {
	fmt.Print(`
Available commands:
  connect <network_type>    Join the network (Public, Hybrid, Private)
  cd <path>                 Change working directory
  pwd                       Print working directory
  ls [path]                 List files at path
  cp <src> <dst>            Copy a file
  rm <path>                 Remove a file
  share <file> <peer_id>    Share a file with a peer
  revoke <file> <peer_id>   Revoke access to a file
  help                      Show this help message
  exit                      Exit the CLI
`)
}

// Close closes the IPC connection.
func (s *Shell) Close() error {
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		s.encoder = nil
		s.decoder = nil
		return err
	}
	return nil
}
