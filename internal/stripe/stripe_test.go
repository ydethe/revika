package stripe

import (
	"bytes"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/store"
)

// mkDesc builds a K=k, M=m descriptor whose shard IDs are deterministic so tests
// can reason about position order.
func mkDesc(k, m int) Descriptor {
	n := k + m
	shards := make([]store.ShardID, n)
	for i := range shards {
		shards[i] = store.HashOf([]byte{byte(i), 0xab})
	}
	return Descriptor{K: k, M: m, Shards: shards}
}

func TestDescriptorMarshalRoundTrip(t *testing.T) {
	d := mkDesc(4, 2)
	b, err := d.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := 6 + 6*idSize; len(b) != want {
		t.Fatalf("marshal length = %d, want %d", len(b), want)
	}
	got, err := UnmarshalDescriptor(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.K != d.K || got.M != d.M {
		t.Fatalf("params = %d/%d, want %d/%d", got.K, got.M, d.K, d.M)
	}
	for i := range d.Shards {
		if got.Shards[i] != d.Shards[i] {
			t.Fatalf("shard %d differs after round trip", i)
		}
	}
}

func TestUnmarshalRejectsMalformed(t *testing.T) {
	d := mkDesc(4, 2)
	b, _ := d.MarshalBinary()

	cases := map[string][]byte{
		"too short":      b[:3],
		"truncated body": b[:len(b)-1],
		"trailing byte":  append(append([]byte{}, b...), 0x00),
	}
	for name, bad := range cases {
		if _, err := UnmarshalDescriptor(bad); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}

	// N inconsistent with K+M.
	badNM := append([]byte{}, b...)
	badNM[5] = byte(b[5] + 1) // bump low byte of N
	if _, err := UnmarshalDescriptor(badNM); err == nil {
		t.Errorf("mismatched N: expected error, got nil")
	}
}

func TestMarshalRejectsBadParams(t *testing.T) {
	if _, err := (Descriptor{K: 0, M: 2, Shards: nil}).MarshalBinary(); err == nil {
		t.Errorf("K=0: expected error")
	}
	if _, err := (Descriptor{K: 4, M: 2, Shards: make([]store.ShardID, 5)}).MarshalBinary(); err == nil {
		t.Errorf("wrong shard count: expected error")
	}
}

func TestContains(t *testing.T) {
	d := mkDesc(2, 1)
	if !d.Contains(d.Shards[1]) {
		t.Errorf("Contains(member) = false")
	}
	if d.Contains(store.HashOf([]byte("not in stripe"))) {
		t.Errorf("Contains(non-member) = true")
	}
}

func TestGrantVerifyAcceptsValid(t *testing.T) {
	sk, pk, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	d := mkDesc(4, 2)
	grant, err := BuildGrant(sk, d, 0)
	if err != nil {
		t.Fatalf("build grant: %v", err)
	}
	if len(grant) != GrantSize {
		t.Fatalf("grant size = %d, want %d", len(grant), GrantSize)
	}
	owner, err := VerifyGrant(grant, d, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !bytes.Equal(owner, pk[:]) {
		t.Fatalf("owner = %x, want %x", owner, pk[:])
	}
}

func TestGrantVerifyRejects(t *testing.T) {
	sk, _, _ := cap.GenerateSigningKey()
	other, _, _ := cap.GenerateSigningKey()
	d := mkDesc(4, 2)
	grant, _ := BuildGrant(sk, d, 0)

	t.Run("wrong owner", func(t *testing.T) {
		g, _ := BuildGrant(other, d, 0)
		// A grant from `other` should still verify under its own key — but not
		// bind to sk's owner. Confirm cross-key confusion is impossible by
		// tampering the owner bytes of sk's grant to `other`'s pubkey.
		tampered := append([]byte{}, grant...)
		copy(tampered[:cap.SignPubKeySize], g[:cap.SignPubKeySize])
		if _, err := VerifyGrant(tampered, d, time.Unix(1000, 0)); err == nil {
			t.Errorf("tampered owner: expected error")
		}
	})

	t.Run("tampered descriptor K/M", func(t *testing.T) {
		bad := d
		bad.K, bad.M = 3, 3 // same N=6 but different params → different signed bytes
		if _, err := VerifyGrant(grant, bad, time.Unix(1000, 0)); err == nil {
			t.Errorf("tampered K/M: expected error")
		}
	})

	t.Run("tampered shard set", func(t *testing.T) {
		bad := Descriptor{K: d.K, M: d.M, Shards: append([]store.ShardID{}, d.Shards...)}
		bad.Shards[0] = store.HashOf([]byte("evil"))
		if _, err := VerifyGrant(grant, bad, time.Unix(1000, 0)); err == nil {
			t.Errorf("tampered shard: expected error")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		if _, err := VerifyGrant(grant[:GrantSize-1], d, time.Unix(1000, 0)); err == nil {
			t.Errorf("short grant: expected error")
		}
	})

	t.Run("expired", func(t *testing.T) {
		exp, _ := BuildGrant(sk, d, 500)
		if _, err := VerifyGrant(exp, d, time.Unix(1000, 0)); err == nil {
			t.Errorf("expired grant: expected error")
		}
		if _, err := VerifyGrant(exp, d, time.Unix(100, 0)); err != nil {
			t.Errorf("not-yet-expired grant: unexpected error %v", err)
		}
	})
}

// TestGrantNonceUnique verifies that two grants built for the same stripe and
// expiry produce different nonces, so each grant is independently revocable.
func TestGrantNonceUnique(t *testing.T) {
	sk, _, _ := cap.GenerateSigningKey()
	d := mkDesc(4, 2)
	g1, err := BuildGrant(sk, d, 0)
	if err != nil {
		t.Fatalf("build g1: %v", err)
	}
	g2, err := BuildGrant(sk, d, 0)
	if err != nil {
		t.Fatalf("build g2: %v", err)
	}
	n1, err := GrantNonce(g1)
	if err != nil {
		t.Fatalf("nonce g1: %v", err)
	}
	n2, err := GrantNonce(g2)
	if err != nil {
		t.Fatalf("nonce g2: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Errorf("consecutive grants have identical nonces (%x): revocation would invalidate both", n1)
	}
}

// TestGrantNonceTamperedFails verifies that mutating the nonce byte range in a
// valid grant breaks signature verification, so a tampered nonce is detected.
func TestGrantNonceTamperedFails(t *testing.T) {
	sk, _, _ := cap.GenerateSigningKey()
	d := mkDesc(4, 2)
	grant, _ := BuildGrant(sk, d, 0)

	tampered := append([]byte{}, grant...)
	// Flip the first nonce byte (at grantNonceOffset).
	tampered[grantNonceOffset] ^= 0xff
	if _, err := VerifyGrant(tampered, d, time.Unix(0, 0)); err == nil {
		t.Errorf("tampered nonce: expected VerifyGrant to return an error")
	}
}

// TestGrantNonceHelperErrors verifies that GrantNonce rejects a grant that is
// not exactly GrantSize bytes.
func TestGrantNonceHelperErrors(t *testing.T) {
	sk, _, _ := cap.GenerateSigningKey()
	d := mkDesc(4, 2)
	grant, _ := BuildGrant(sk, d, 0)

	// Short by one byte.
	if _, err := GrantNonce(grant[:GrantSize-1]); err == nil {
		t.Errorf("short grant: expected error from GrantNonce")
	}
	// Correct length: must succeed.
	if _, err := GrantNonce(grant); err != nil {
		t.Errorf("valid grant: unexpected GrantNonce error: %v", err)
	}
}
