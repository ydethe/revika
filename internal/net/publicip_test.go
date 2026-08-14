package net

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverPublicIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(" 203.0.113.7\n"))
	}))
	t.Cleanup(server.Close)

	ip, err := discoverPublicIP(context.Background(), server.URL, server.Client())
	if err != nil {
		t.Fatalf("discover public IP: %v", err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("discovered IP = %q, want 203.0.113.7", ip)
	}
}

func TestDiscoverPublicIPRejectsInvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-an-ip"))
	}))
	t.Cleanup(server.Close)

	if _, err := discoverPublicIP(context.Background(), server.URL, server.Client()); err == nil {
		t.Fatal("expected invalid public IP response to fail")
	}
}
