package provider

import (
	"testing"

	"revika/internal/cap"
	"revika/internal/device"
	"revika/internal/manifest"
	"revika/internal/store"
)

func mustDevice(t *testing.T) cap.PublicKey {
	t.Helper()
	_, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return pub
}

// TestDeviceAuthCodecRoundTrip round-trips a signed device-authorization record
// through Encode/Decode and confirms the decoded record still verifies (the DHT
// validator depends on this) and preserves every field.
func TestDeviceAuthCodecRoundTrip(t *testing.T) {
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	d1, d2 := mustDevice(t), mustDevice(t)
	a, _ := device.Auth{}.With(d1, "laptop")
	a, _ = a.With(d2, "phone")
	a = a.Sign(sk)

	data, err := EncodeDeviceAuth(a)
	if err != nil {
		t.Fatalf("EncodeDeviceAuth: %v", err)
	}
	got, err := DecodeDeviceAuth(data)
	if err != nil {
		t.Fatalf("DecodeDeviceAuth: %v", err)
	}
	if !got.Verify() {
		t.Fatal("decoded device-auth record failed to verify")
	}
	if got.Owner != a.Owner || got.Seq != a.Seq || len(got.Members) != len(a.Members) {
		t.Fatal("decoded record differs in owner/seq/member-count")
	}
	if !got.Authorized(device.NewID(d1)) || !got.Authorized(device.NewID(d2)) {
		t.Fatal("decoded record lost an authorized device")
	}
}

// TestDeviceAuthDecodeRejectsGarbage ensures malformed input is a clean error,
// not a panic.
func TestDeviceAuthDecodeRejectsGarbage(t *testing.T) {
	if _, err := DecodeDeviceAuth([]byte("not json")); err == nil {
		t.Fatal("garbage should not decode")
	}
	if _, err := DecodeDeviceAuth([]byte(`{"owner":"!!!","seq":1}`)); err == nil {
		t.Fatal("malformed owner should error")
	}
}

// TestFullRootSealsCodecRoundTrip round-trips a device-scoped companion (Seals,
// no legacy Sealed) and a legacy companion (Sealed, no Seals), confirming both
// survive Encode/Decode and still verify.
func TestFullRootSealsCodecRoundTrip(t *testing.T) {
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, pub1, _ := cap.GenerateIdentity()
	_, pub2, _ := cap.GenerateIdentity()
	root := manifest.ReadCap{Kind: manifest.KindDir, K: 4, M: 2, Shards: []store.ShardID{{1}, {2}, {3}, {4}, {5}, {6}}}

	// Device-scoped: Seals set, Sealed empty.
	rec, err := manifest.SealFullRootFor(sk, []cap.PublicKey{pub1, pub2}, root, 9)
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeFullRoot(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFullRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sealed) != 0 || len(got.Seals) != 2 || !got.Verify() {
		t.Fatalf("device-scoped round-trip wrong: sealed=%d seals=%d verify=%v", len(got.Sealed), len(got.Seals), got.Verify())
	}

	// Legacy single-owner: Sealed set, Seals empty — must still round-trip.
	legacy, err := manifest.SealFullRoot(sk, pub1, root, 3)
	if err != nil {
		t.Fatal(err)
	}
	ldata, err := EncodeFullRoot(legacy)
	if err != nil {
		t.Fatal(err)
	}
	lgot, err := DecodeFullRoot(ldata)
	if err != nil {
		t.Fatal(err)
	}
	if len(lgot.Sealed) == 0 || len(lgot.Seals) != 0 || !lgot.Verify() {
		t.Fatalf("legacy round-trip wrong: sealed=%d seals=%d verify=%v", len(lgot.Sealed), len(lgot.Seals), lgot.Verify())
	}
}
