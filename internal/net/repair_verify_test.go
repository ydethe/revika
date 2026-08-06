package net

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"revika/internal/cap"
	"revika/internal/store"
	"revika/internal/stripe"
)

// lyingShardHandler answers HAS with "present" but cannot serve the bytes on GET
// — a node that lies about holding a shard. It is the misbehaviour the repair
// possession-verify option (RepairStore.SetVerifyPossession) exists to catch.
func lyingShardHandler(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	opByte, err := readByte(s)
	if err != nil {
		_ = s.Reset()
		return
	}
	if _, err := readID(s); err != nil {
		_ = s.Reset()
		return
	}
	switch op(opByte) {
	case opHas:
		_ = writeByte(s, byte(statusOK))
		_ = writeByte(s, 1) // the lie: claim possession we cannot back up
	default: // GET (and anything else): we do not actually hold the bytes
		_ = writeByte(s, byte(statusNotFound))
	}
}

// TestRepairVerifyCatchesLyingHolder is the point of the -repair-verify option:
// a node that answers HAS=present but cannot serve the shard defeats the cheap
// presence-byte check, but a proof-of-retrieval check (fetch + self-verify) sees
// through it and counts the shard missing so repair regenerates it.
func TestRepairVerifyCatchesLyingHolder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	data := []byte("a shard the liar only pretends to hold")
	id := store.HashOf(data)

	// A liar that announces a provider record for id but serves no bytes.
	liar := newDHTNode(t, DHTModeServer, store.NewMemStore())
	liar.h.SetStreamHandler(ShardProtocol, lyingShardHandler)
	liar.h.SetStreamHandler(ShardProtocolV1, lyingShardHandler)

	repairer := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(liar))
	waitRoutingTable(t, repairer)
	waitRoutingTable(t, liar)

	actx, acancel := context.WithTimeout(ctx, 15*time.Second)
	if err := liar.Announce(actx, id); err != nil {
		t.Fatalf("liar announce: %v", err)
	}
	acancel()
	waitProviders(t, repairer, id)

	rs := NewRepairStore(repairer.h, nil, repairer, descFor(id), nil)

	// Verify OFF: the cheap check trusts the liar's presence byte and is fooled —
	// this documents exactly the weakness the option closes.
	if ok, err := rs.Has(ctx, id); err != nil || !ok {
		t.Fatalf("verify-off Has = (%v, %v), want (true, nil): the presence-byte check should trust the liar", ok, err)
	}

	// Verify ON: the shard is fetched and self-verified; the liar cannot produce it,
	// so the shard is correctly reported missing.
	rs.SetVerifyPossession(true)
	if ok, err := rs.Has(ctx, id); err != nil || ok {
		t.Fatalf("verify-on Has = (%v, %v), want (false, nil): a lying holder must be caught", ok, err)
	}
}

// TestRepairVerifyAcceptsGenuineHolder confirms the possession-verify path does
// not false-positive: a genuinely held-and-announced shard verifies present, and
// an absent one verifies missing.
func TestRepairVerifyAcceptsGenuineHolder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	holderStore := store.NewMemStore()
	holder, _ := newDHTLedgerNode(t, holderStore)
	repairer := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(holder))
	waitRoutingTable(t, repairer)
	waitRoutingTable(t, holder)

	signer, _, _ := cap.GenerateSigningKey()
	data := []byte("a shard genuinely stored and announced")
	id := store.HashOf(data)
	desc := descFor(id)
	grant, err := stripe.BuildGrant(signer, desc, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Seed the shard onto the holder (grant-authorized) so it stores AND announces.
	if _, err := NewNetStore(repairer.h, holder.h.ID()).putGrant(ctx, data, desc, grant, ReasonRepair); err != nil {
		t.Fatalf("seed holder: %v", err)
	}
	waitProviders(t, repairer, id)

	rs := NewRepairStore(repairer.h, nil, repairer, desc, grant)
	rs.SetVerifyPossession(true)

	if ok, err := rs.Has(ctx, id); err != nil || !ok {
		t.Fatalf("verify-on Has for a genuine holder = (%v, %v), want (true, nil)", ok, err)
	}
	// An absent shard verifies missing, not errored.
	if ok, err := rs.Has(ctx, store.HashOf([]byte("nobody holds this"))); err != nil || ok {
		t.Fatalf("verify-on Has for an absent shard = (%v, %v), want (false, nil)", ok, err)
	}
}
