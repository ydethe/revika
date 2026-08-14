package net

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"strings"
	"time"
)

const publicIPServiceURL = "https://api.ipify.org"

// DiscoverPublicIP returns the node's public IPv4 or IPv6 address as reported
// by the external lookup service. The caller should use a bounded context.
func DiscoverPublicIP(ctx context.Context) (string, error) {
	return discoverPublicIP(ctx, publicIPServiceURL, &http.Client{Timeout: 5 * time.Second})
}

func discoverPublicIP(ctx context.Context, serviceURL string, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serviceURL, nil)
	if err != nil {
		return "", fmt.Errorf("create public IP request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("query public IP service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("public IP service returned HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", fmt.Errorf("read public IP response: %w", err)
	}
	ip := strings.TrimSpace(string(body))
	parsed := stdnet.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("public IP service returned invalid IP %q", ip)
	}
	return parsed.String(), nil
}
