package device

import (
	"testing"

	"revika/internal/cap"
)

// newDevice mints a fresh ML-KEM keypair standing in for one device's identity.
func newDevice(t *testing.T) cap.PublicKey {
	t.Helper()
	_, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return pub
}

func newOwner(t *testing.T) cap.SignKey {
	t.Helper()
	sk, _, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	return sk
}

func TestSignVerifyRoundTrip(t *testing.T) {
	owner := newOwner(t)
	d1 := newDevice(t)
	d2 := newDevice(t)

	a, err := Auth{}.With(d1, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	a, err = a.With(d2, "phone")
	if err != nil {
		t.Fatal(err)
	}
	a = a.Sign(owner)

	if a.Seq != 2 {
		t.Fatalf("Seq = %d, want 2 (two enrolls)", a.Seq)
	}
	if !a.Verify() {
		t.Fatal("freshly signed record failed Verify")
	}
	if a.Owner != owner.Public() {
		t.Fatal("Sign did not stamp the owner")
	}
	if !a.Authorized(NewID(d1)) || !a.Authorized(NewID(d2)) {
		t.Fatal("enrolled devices not authorized")
	}
	if len(a.Recipients()) != 2 {
		t.Fatalf("Recipients len = %d, want 2", len(a.Recipients()))
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	owner := newOwner(t)
	d1 := newDevice(t)
	a, _ := Auth{}.With(d1, "laptop")
	a = a.Sign(owner)

	// Tamper with the label: signature must no longer verify.
	bad := a.clone()
	bad.Members[0].Label = "attacker"
	if bad.Verify() {
		t.Fatal("tampered label still verified")
	}

	// Swap the signing key: a different owner's signature must not verify.
	other := newOwner(t)
	bad2 := a.clone()
	bad2.Owner = other.Public()
	if bad2.Verify() {
		t.Fatal("record verified under the wrong owner")
	}

	// A member whose ID does not derive from its Pub is rejected even if signed,
	// because Verify recomputes the ID.
	d2 := newDevice(t)
	bad3, _ := Auth{}.With(d1, "laptop")
	bad3.Members[0].Pub = d2 // ID still hashes d1, Pub is d2 → mismatch
	bad3 = bad3.Sign(owner)
	if bad3.Verify() {
		t.Fatal("member with mismatched ID/Pub verified")
	}
}

// TestSignatureOrderIndependent proves the canonical member sort makes the
// signed payload independent of the slice order the members happen to be stored
// in: the identical member set, held in reversed order, yields the same payload.
func TestSignatureOrderIndependent(t *testing.T) {
	d1 := newDevice(t)
	d2 := newDevice(t)
	m1 := Member{ID: NewID(d1), Pub: d1, Label: "a", Added: 1}
	m2 := Member{ID: NewID(d2), Pub: d2, Label: "b", Added: 2}

	a := Auth{Seq: 2, Members: []Member{m1, m2}}
	b := Auth{Seq: 2, Members: []Member{m2, m1}}
	if string(a.signingPayload()) != string(b.signingPayload()) {
		t.Fatal("signing payload depends on stored member order")
	}
}

func TestWithRejectsDuplicate(t *testing.T) {
	d1 := newDevice(t)
	a, err := Auth{}.With(d1, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.With(d1, "again"); err == nil {
		t.Fatal("re-adding an authorized device should error")
	}
}

func TestWithoutRevokes(t *testing.T) {
	owner := newOwner(t)
	d1 := newDevice(t)
	d2 := newDevice(t)
	a, _ := Auth{}.With(d1, "laptop")
	a, _ = a.With(d2, "phone")
	a = a.Sign(owner)

	revoked, err := a.Without(NewID(d1))
	if err != nil {
		t.Fatal(err)
	}
	revoked = revoked.Sign(owner)

	if revoked.Seq != a.Seq+1 {
		t.Fatalf("revoke Seq = %d, want %d", revoked.Seq, a.Seq+1)
	}
	if revoked.Authorized(NewID(d1)) {
		t.Fatal("revoked device still authorized")
	}
	if !revoked.Authorized(NewID(d2)) {
		t.Fatal("survivor was dropped by revoke")
	}
	if len(revoked.Recipients()) != 1 {
		t.Fatalf("survivor recipients = %d, want 1", len(revoked.Recipients()))
	}

	// Revoking an absent device is an error, not a silent no-op.
	if _, err := a.Without(NewID(newDevice(t))); err == nil {
		t.Fatal("revoking an absent device should error")
	}
}

func TestResolveHandle(t *testing.T) {
	owner := newOwner(t)
	d1 := newDevice(t)
	a, _ := Auth{}.With(d1, "laptop")
	a = a.Sign(owner)

	id := NewID(d1)
	// Full and short prefixes both resolve to the one member.
	for _, h := range []string{id.String(), id.Short(), id.String()[:4]} {
		m, err := a.Resolve(h)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", h, err)
		}
		if m.ID != id {
			t.Fatalf("Resolve(%q) got %s", h, m.ID)
		}
	}

	if _, err := a.Resolve(""); err == nil {
		t.Fatal("empty handle should error")
	}
	if _, err := a.Resolve("ffffffffff"); err == nil {
		t.Fatal("unknown handle should error")
	}
}
