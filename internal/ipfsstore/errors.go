package ipfsstore

import (
	"errors"
	"fmt"
	"strings"
)

// apiError carries a non-2xx Kubo RPC response so callers can classify it. Kubo reports a
// missing MFS path with HTTP 500 and a "file does not exist" message rather than a 404, so
// isNotExist inspects both the status and the body.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("ipfs api: status %d: %s", e.status, strings.TrimSpace(e.message))
}

// isNotExist reports whether err is a Kubo "path does not exist" response.
func isNotExist(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	message := strings.ToLower(apiErr.message)
	return strings.Contains(message, "does not exist") ||
		strings.Contains(message, "no link named") ||
		strings.Contains(message, "not found")
}
