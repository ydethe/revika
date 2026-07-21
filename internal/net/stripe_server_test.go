package net

import (
	"context"
	"errors"
	"testing"

	"revika/internal/cap"
	"revika/internal/ledger"
	"revika/internal/store"
	"revika/internal/stripe"
)

// descFor builds a valid K=1,M=1 descriptor whose first shard is id and whose
// second is an arbitrary sibling — enough to exercise the grant/stripe wire paths
// without needing real erasure-coded bytes.
func descFor(id store.ShardID) stripe.Descriptor {
	return stripe.Descriptor{K: 1, M: 1, Shards: []store.ShardID{id, store.HashOf([]byte("sibling-shard"))}}
}

// TestPutStripeRecordsStripe checks that a normal (token-authorized) PutStripe
// both stores the shard and records its stripe context in the ledger, so the node
// can later take part in repairing it.
func TestPutStripeRecordsStripe(t *testing.T) {
	backing := store.NewMemStore()
	server, led := newLedgerNode(t, backing, ledger.Options{})
	key, _, _ := cap.GenerateSigningKey()
	c := signedClient(t, server, key)
	ctx := context.Background()

	data := []byte("shard bytes for a stripe")
	id := store.HashOf(data)
	desc := descFor(id)

	got, err := c.PutStripe(ctx, data, desc)
	if err != nil {
		t.Fatalf("PutStripe: %v", err)
	}
	if got != id {
		t.Fatalf("PutStripe id = %s, want %s", got, id)
	}

	rows, err := led.Stripes()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d stripe rows, want 1", len(rows))
	}
	if rows[0].ShardID != id || rows[0].K != 1 || rows[0].M != 1 {
		t.Fatalf("stripe row = %+v, want shard=%s 1/1", rows[0], id)
	}
	if len(rows[0].Grant) != stripe.GrantSize {
		t.Fatalf("recorded grant is %d bytes, want %d", len(rows[0].Grant), stripe.GrantSize)
	}
}

// TestGrantPutAccepted is the repair-authorization path: a client holding NO
// signing key stores a shard purely on the strength of a repair grant, and the
// node records ownership under the granting User plus the stripe context.
func TestGrantPutAccepted(t *testing.T) {
	backing := store.NewMemStore()
	server, led := newLedgerNode(t, backing, ledger.Options{})
	ctx := context.Background()

	signer, ownerPub, _ := cap.GenerateSigningKey()
	data := []byte("a regenerated shard")
	id := store.HashOf(data)
	desc := descFor(id)
	grant, err := stripe.BuildGrant(signer, desc, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The repairing node holds no User key — it replays the distributed grant.
	repairer := NewNetStore(clientHost(t, server), server.ID())
	got, err := repairer.putGrant(ctx, data, desc, grant)
	if err != nil {
		t.Fatalf("putGrant: %v", err)
	}
	if got != id {
		t.Fatalf("putGrant id = %s, want %s", got, id)
	}
	if ok, _ := backing.Has(ctx, id); !ok {
		t.Fatal("shard not stored after grant PUT")
	}

	// Ownership is attributed to the granting User, and the stripe is recorded.
	used, n, _ := led.Account(ownerPub[:])
	if n != 1 || used != int64(len(data)) {
		t.Fatalf("owner account = %d bytes / %d shards, want %d/1", used, n, len(data))
	}
	rows, _ := led.Stripes()
	if len(rows) != 1 {
		t.Fatalf("stripe rows = %d, want 1", len(rows))
	}
}

// TestGrantPutRejected covers the ways a grant PUT must be refused.
func TestGrantPutRejected(t *testing.T) {
	ctx := context.Background()
	signer, _, _ := cap.GenerateSigningKey()
	dataIn := []byte("in-stripe shard")
	desc := descFor(store.HashOf(dataIn))
	grant, _ := stripe.BuildGrant(signer, desc, 0)

	t.Run("shard not in stripe", func(t *testing.T) {
		backing := store.NewMemStore()
		server, _ := newLedgerNode(t, backing, ledger.Options{})
		repairer := NewNetStore(clientHost(t, server), server.ID())
		foreign := []byte("bytes not named by the grant's stripe")
		if _, err := repairer.putGrant(ctx, foreign, desc, grant); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("foreign-shard grant PUT = %v, want ErrUnauthorized", err)
		}
		if ok, _ := backing.Has(ctx, store.HashOf(foreign)); ok {
			t.Fatal("foreign shard was stored despite grant scope")
		}
	})

	t.Run("tampered grant", func(t *testing.T) {
		backing := store.NewMemStore()
		server, _ := newLedgerNode(t, backing, ledger.Options{})
		repairer := NewNetStore(clientHost(t, server), server.ID())
		bad := append([]byte(nil), grant...)
		bad[len(bad)-1] ^= 0xff
		if _, err := repairer.putGrant(ctx, dataIn, desc, bad); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("tampered grant PUT = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("no token and no grant", func(t *testing.T) {
		backing := store.NewMemStore()
		server, _ := newLedgerNode(t, backing, ledger.Options{})
		repairer := NewNetStore(clientHost(t, server), server.ID())
		if _, err := repairer.putRaw(ctx, dataIn, nil, nil, nil); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("unauthenticated PUT = %v, want ErrUnauthorized", err)
		}
	})
}

// TestNilLedgerAcceptsStripeFrame confirms the 1.1.0 four-blob frame is backward
// compatible with a node that runs no ledger: it stores the bytes and ignores the
// stripe descriptor and grant.
func TestNilLedgerAcceptsStripeFrame(t *testing.T) {
	backing := store.NewMemStore()
	serverHost, err := NewHost(HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { serverHost.Close() })
	NewServer(backing, nil).Register(serverHost) // no ledger

	signer, _, _ := cap.GenerateSigningKey()
	c := NewNetStoreSigned(clientHost(t, serverHost), serverHost.ID(), signer)
	ctx := context.Background()

	data := []byte("stored against a ledgerless node")
	id := store.HashOf(data)
	got, err := c.PutStripe(ctx, data, descFor(id))
	if err != nil {
		t.Fatalf("PutStripe against nil-ledger node: %v", err)
	}
	if got != id {
		t.Fatalf("id = %s, want %s", got, id)
	}
	if ok, _ := backing.Has(ctx, id); !ok {
		t.Fatal("shard not stored")
	}
}
