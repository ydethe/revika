package cap

import (
	"context"
	"testing"
	"time"
)

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{nil, 0},
		{[]byte{0xFF}, 0},
		{[]byte{0x7F}, 1},
		{[]byte{0x01}, 7},
		{[]byte{0x00}, 8},
		{[]byte{0x00, 0x80}, 8},
		{[]byte{0x00, 0x00, 0x10}, 19},
	}
	for _, c := range cases {
		if got := leadingZeroBits(c.in); got != c.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", c.in, got, c.want)
		}
	}
}

// testPuzzles returns the puzzle under test with tiny parameters so the test
// stays fast — production params come from DefaultArgon2id.
func testPuzzles() []Argon2idPuzzle {
	return []Argon2idPuzzle{
		{Time: 1, Memory: 8, Threads: 1},
	}
}

func TestPuzzleDeterministic(t *testing.T) {
	_, pub, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range testPuzzles() {
		a := p.Sum(pub[:])
		b := p.Sum(pub[:])
		if string(a) != string(b) {
			t.Errorf("%s: Sum not deterministic", p.Name())
		}
		if len(a) == 0 {
			t.Errorf("%s: empty digest", p.Name())
		}
	}
}

func TestMeetsPoWZeroDifficultyAlwaysPasses(t *testing.T) {
	for _, p := range testPuzzles() {
		if !MeetsPoW(p, []byte("anything"), 0) {
			t.Errorf("%s: difficulty 0 should always pass", p.Name())
		}
	}
}

func TestMintProducesValidSelfCertifyingKey(t *testing.T) {
	for _, p := range testPuzzles() {
		// Difficulty 8 => ~256 attempts expected; cheap and deterministic to verify.
		const d Difficulty = 8
		var lastAttempts uint64
		key, pub, err := MintSigningKey(p, d, func(pr Progress) { lastAttempts = pr.Attempts })
		if err != nil {
			t.Fatalf("%s: MintSigningKey: %v", p.Name(), err)
		}
		if !MeetsPoW(p, pub[:], d) {
			t.Errorf("%s: minted key does not meet difficulty %d", p.Name(), d)
		}
		// The minted key must be a usable signing keypair.
		if key.Public() != pub {
			t.Errorf("%s: minted private key does not derive the returned public key", p.Name())
		}
		msg := []byte("owner asserts a write")
		if !pub.Verify(msg, key.Sign(msg)) {
			t.Errorf("%s: minted key cannot sign/verify", p.Name())
		}
		if lastAttempts == 0 {
			t.Errorf("%s: expected progress callback to report attempts", p.Name())
		}
	}
}

func TestMintCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	// Difficulty 64 is effectively unreachable in the timeout, so the mint must
	// return the context error rather than hang.
	_, _, err := MintSigningKeyContext(ctx, Argon2idPuzzle{Time: 1, Memory: 8, Threads: 1}, 64, nil)
	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}
}

// TestMintZeroPuzzleDefaults confirms the zero-value puzzle is filled in with
// DefaultArgon2id rather than producing an invalid (zero-memory) Argon2id call.
func TestMintZeroPuzzleDefaults(t *testing.T) {
	// Difficulty 0 accepts the first key, so this returns immediately even though
	// DefaultArgon2id's parameters are heavy.
	if _, _, err := MintSigningKey(Argon2idPuzzle{}, 0, nil); err != nil {
		t.Fatalf("mint with zero-value puzzle: %v", err)
	}
}
