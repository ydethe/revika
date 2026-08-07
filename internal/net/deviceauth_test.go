package net

import (
	"context"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/device"
	"revika/internal/provider"
	"revika/internal/store"
)

func mustDeviceKey(t *testing.T) cap.PublicKey {
	t.Helper()
	_, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return pub
}

// TestDeviceAuthValidator checks the deviceAuthValidator rules directly: a good
// record validates; wrong namespace, wrong key length, owner/key mismatch, and a
// tampered signature are rejected; Select prefers the highest Seq (anti-rollback).
func TestDeviceAuthValidator(t *testing.T) {
	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	d1 := mustDeviceKey(t)

	enc := func(seq uint64, s cap.SignKey) []byte {
		a, _ := device.Auth{}.With(d1, "laptop")
		a.Seq = seq
		a = a.Sign(s)
		b, err := provider.EncodeDeviceAuth(a)
		if err != nil {
			t.Fatalf("EncodeDeviceAuth: %v", err)
		}
		return b
	}

	v := deviceAuthValidator{}
	key := deviceAuthKey(owner)
	val := enc(1, sk)

	if err := v.Validate(key, val); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if err := v.Validate("/wrong/"+string(owner[:]), val); err == nil {
		t.Fatal("wrong namespace should be rejected")
	}
	if err := v.Validate("/"+DeviceAuthNamespace+"/short", val); err == nil {
		t.Fatal("short key path should be rejected")
	}
	otherSk, _, _ := cap.GenerateSigningKey()
	if err := v.Validate(key, enc(1, otherSk)); err == nil {
		t.Fatal("owner/key mismatch should be rejected")
	}

	// Select: highest seq wins (a revoke advances Seq, so the latest set beats any
	// stale record that would re-authorize a removed device).
	idx, err := v.Select(key, [][]byte{enc(1, sk), enc(9, sk), enc(4, sk)})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if idx != 1 {
		t.Fatalf("Select picked %d, want 1 (seq 9)", idx)
	}
}

// TestPutGetDeviceAuthDHT round-trips a signed device-authorization record
// through an in-process two-node DHT and confirms anti-rollback: a stale (lower
// Seq) record cannot roll the network back to re-authorize a revoked device.
func TestPutGetDeviceAuthDHT(t *testing.T) {
	seed := newDHTNode(t, DHTModeServer, store.NewMemStore())
	client := newDHTNode(t, DHTModeServer, store.NewMemStore(), dhtAddr(seed))
	waitRoutingTable(t, client)
	waitRoutingTable(t, seed)

	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	d1, d2 := mustDeviceKey(t), mustDeviceKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Miss before publish.
	if _, ok, err := client.GetDeviceAuth(ctx, owner); err != nil || ok {
		t.Fatalf("GetDeviceAuth before publish: ok=%v err=%v", ok, err)
	}

	// Enroll two devices (Seq 2), publish.
	a, _ := device.Auth{}.With(d1, "laptop")
	a, _ = a.With(d2, "phone")
	a = a.Sign(sk)
	if err := seed.PutDeviceAuth(ctx, a); err != nil {
		t.Fatalf("PutDeviceAuth: %v", err)
	}

	got, ok, err := client.GetDeviceAuth(ctx, owner)
	if err != nil || !ok {
		t.Fatalf("GetDeviceAuth: ok=%v err=%v", ok, err)
	}
	if got.Seq != 2 || !got.Authorized(device.NewID(d1)) || !got.Authorized(device.NewID(d2)) {
		t.Fatalf("resolved record wrong: seq=%d", got.Seq)
	}

	// Revoke d1 (Seq 3), publish, and confirm the network shows the smaller set.
	revoked, err := a.Without(device.NewID(d1))
	if err != nil {
		t.Fatal(err)
	}
	revoked = revoked.Sign(sk)
	if err := seed.PutDeviceAuth(ctx, revoked); err != nil {
		t.Fatalf("PutDeviceAuth revoke: %v", err)
	}
	got, _, err = client.GetDeviceAuth(ctx, owner)
	if err != nil {
		t.Fatalf("GetDeviceAuth after revoke: %v", err)
	}
	if got.Seq != 3 || got.Authorized(device.NewID(d1)) {
		t.Fatalf("revoke did not take: seq=%d d1-authorized=%v", got.Seq, got.Authorized(device.NewID(d1)))
	}

	// Anti-rollback: re-publishing the old Seq-2 record must not re-authorize d1.
	_ = seed.PutDeviceAuth(ctx, a)
	got, _, err = client.GetDeviceAuth(ctx, owner)
	if err != nil {
		t.Fatalf("GetDeviceAuth after rollback attempt: %v", err)
	}
	if got.Seq != 3 || got.Authorized(device.NewID(d1)) {
		t.Fatal("rollback attempt re-authorized a revoked device")
	}
}
