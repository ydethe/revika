package provider

import (
	"bytes"
	"testing"
)

func TestSyncAnchorRoundTrip(t *testing.T) {
	want := SyncAnchor{Sequence: 42, Root: []byte("root-cap")}
	got, err := ParseAnchor(want.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != want.Sequence || !bytes.Equal(got.Root, want.Root) {
		t.Fatalf("anchor = %#v, want %#v", got, want)
	}
	want.Root[0] ^= 1
	if got.Root[0] == want.Root[0] {
		t.Fatal("ParseAnchor did not copy root bytes")
	}
}

func TestCapabilitiesHasAllRequiredBits(t *testing.T) {
	caps := CapRead | CapWrite | CapDelete
	if !caps.Has(CapRead | CapDelete) {
		t.Fatal("capabilities should contain all requested bits")
	}
	if caps.Has(CapRename) {
		t.Fatal("capabilities should not contain ungranted bits")
	}
}
