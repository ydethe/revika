package net

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
	"revika/internal/stripe"
)

// newRevokeNode spins up a ledger-backed server for grant-revocation tests and
// returns the ledger, the backing store, and a signed client.
func newRevokeNode(t *testing.T, signer cap.SignKey) (*ledger.Ledger, *store.MemStore, *NetStore) {
	t.Helper()
	h, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	led, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"), ledger.Options{})
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { led.Close() })
	backing := store.NewMemStore()
	srv := NewServer(backing, nil)
	srv.SetLedger(led)
	srv.Register(h)
	return led, backing, signedClient(t, h, signer)
}

// TestRevokeGrantProtocol is the end-to-end contract: after the owner stores a
// shard via a repair grant and then revokes that grant, any subsequent
// grant-authorized PUT carrying the revoked nonce is refused.
func TestRevokeGrantProtocol(t *testing.T) {
	ctx := context.Background()
	signer, _, _ := cap.GenerateSigningKey()
	led, backing, c := newRevokeNode(t, signer)

	data1 := []byte("shard-one-revoke-test")
	data2 := []byte("shard-two-revoke-test")
	id1 := store.HashOf(data1)
	id2 := store.HashOf(data2)
	desc := stripe.Descriptor{K: 1, M: 1, Shards: []store.ShardID{id1, id2}}

	grant, err := stripe.BuildGrant(signer, desc, 0)
	if err != nil {
		t.Fatalf("BuildGrant: %v", err)
	}
	nonce, err := stripe.GrantNonce(grant)
	if err != nil {
		t.Fatalf("GrantNonce: %v", err)
	}

	// Grant-authorized PUT of shard1 must succeed.
	if _, err := c.putGrant(ctx, data1, desc, grant, ReasonRepair); err != nil {
		t.Fatalf("grant PUT before revocation: %v", err)
	}
	if ok, _ := backing.Has(ctx, id1); !ok {
		t.Fatal("shard1 not stored after grant PUT")
	}

	// Revoke the grant.
	if err := c.RevokeGrant(ctx, nonce); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if revoked, err := led.IsGrantRevoked(nonce); err != nil || !revoked {
		t.Fatalf("IsGrantRevoked after RevokeGrant: revoked=%v err=%v", revoked, err)
	}

	// A second grant-authorized PUT with the same (now-revoked) grant must fail.
	_, err = c.putGrant(ctx, data2, desc, grant, ReasonRepair)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("grant PUT after revocation: got %v, want ErrUnauthorized", err)
	}
	if ok, _ := backing.Has(ctx, id2); ok {
		t.Fatal("shard2 stored despite revoked grant")
	}
}

// TestRevokeGrantRequiresAuth verifies that RevokeGrant is rejected when the
// caller supplies no signer (no auth token can be built).
func TestRevokeGrantRequiresAuth(t *testing.T) {
	ctx := context.Background()
	signer, _, _ := cap.GenerateSigningKey()
	_, _, c := newRevokeNode(t, signer)

	// Build a client with no signer.
	// NetStore.authToken panics/errors when signer is nil — RevokeGrant must
	// surface that as an error before even opening a stream.
	unauthC := &NetStore{h: c.h, peer: c.peer} // signer deliberately nil
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := unauthC.RevokeGrant(ctx, nonce); err == nil {
		t.Fatal("RevokeGrant without signer: expected error, got nil")
	}
}
