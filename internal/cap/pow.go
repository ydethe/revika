package cap

// pow.go makes an owner identity *self-certifying*: a valid Ed25519 owner public
// key must, on its own, satisfy a proof-of-work target. Minting an identity means
// grinding fresh keypairs until one hashes under the target ("Proposal 3a"); the
// public key IS the proof, so it costs seconds-to-minutes of CPU to produce yet
// one hash to verify, and the work is bound to that exact key — a banned owner
// cannot re-mint a usable identity in milliseconds.
//
// The puzzle is Argon2id ("Proposal 3b"): a memory-hard function that flattens
// the GPU/ASIC advantage an attacker would otherwise hold over an honest laptop.
// The difficulty (leading zero bits of the digest) is local policy — no global
// authority or consensus is involved, matching revika's "each node defends
// itself" model. Only the difficulty varies across deployments; the puzzle
// itself is fixed, so a minter and a verifier never have to negotiate which one
// to use.
//
// Quantum note: hash-based PoW stays PQC-class. Grover only halves the effective
// difficulty (a D-bit proof costs ~2^(D/2) quantum evaluations), and memory
// hardness blunts even that; budget by doubling D if it ever matters.
//
// Defence controls (security/Defence.md; primitive P9 in security/frameworks.md):
//   SC-5 (Denial-of-Service Protection) — proof-of-work write admission raises the cost of
//        flooding and of minting fresh identities to replace banned ones (anti-Sybil floor).

import (
	"context"
	"fmt"
	"math/bits"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// powDomain separates revika owner-identity proofs from any other use of the
// same puzzle, and doubles as the (fixed, public) Argon2id salt — verification is
// deterministic, so the salt must be reproducible rather than random.
const powDomain = "revika/pow/owner/v1\x00"

// Difficulty is the proof-of-work target expressed as the number of leading zero
// bits the puzzle digest of a public key must have. Expected minting cost is
// ~2^Difficulty puzzle evaluations; verification is always one evaluation.
// Difficulty 0 accepts any key (proof-of-work disabled).
type Difficulty uint8

// Argon2idPuzzle is the memory-hard puzzle (Argon2id, the password-hashing-competition
// winner) revika uses to certify an owner identity. Because every attempt costs a
// fixed slice of RAM and CPU, an attacker's specialised-hardware advantage over an
// honest machine collapses, so a difficulty painful to grind stays tolerable to
// mint once. Both minting and verification pay one evaluation; verification stays
// O(1) per identity. Sum is a pure, deterministic function of pubkey (plus the
// fixed parameters) so any verifier reproduces the same digest; a key "meets" a
// difficulty when its digest has at least that many leading zero bits.
type Argon2idPuzzle struct {
	Time    uint32 // number of passes over memory
	Memory  uint32 // memory in KiB
	Threads uint8  // lanes / parallelism within one evaluation
}

// DefaultArgon2id returns balanced parameters: 64 MiB, 2 passes, single lane —
// roughly tens of milliseconds per attempt on a current CPU, with a negligible
// GPU speedup. Tune Memory up to harden further.
func DefaultArgon2id() Argon2idPuzzle {
	return Argon2idPuzzle{Time: 2, Memory: 64 * 1024, Threads: 1}
}

// Name renders the puzzle's kind and parameters for logs and CLI display, e.g.
// "argon2id(t=2,m=65536KiB,p=1)".
func (p Argon2idPuzzle) Name() string {
	return fmt.Sprintf("argon2id(t=%d,m=%dKiB,p=%d)", p.Time, p.Memory, p.Threads)
}

// Sum returns the puzzle digest of an owner public key.
func (p Argon2idPuzzle) Sum(pubkey []byte) []byte {
	return argon2.IDKey(pubkey, []byte(powDomain), p.Time, p.Memory, p.Threads, 32)
}

// leadingZeroBits counts the leading zero bits of b (0 for empty input).
func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(x)
	}
	return n
}

// MeetsPoW reports whether pubkey satisfies difficulty d under puzzle: its digest
// has at least d leading zero bits. This is the verifier a node runs against the
// owner pubkey it recovers from an auth token; it is O(1) in the number of
// attempts the minter made. A zero difficulty always passes.
func MeetsPoW(puzzle Argon2idPuzzle, pubkey []byte, d Difficulty) bool {
	if d == 0 {
		return true
	}
	return leadingZeroBits(puzzle.Sum(pubkey)) >= int(d)
}

// Progress reports minting effort so far. It is passed to the MintSigningKey
// callback periodically (and once more on success) so callers can render an
// ssh-keygen-style progress display.
type Progress struct {
	Attempts uint64        // keypairs tried so far, across all workers
	Elapsed  time.Duration // wall-clock since minting started
}

// MintSigningKey grinds fresh Ed25519 signing keypairs until one is a valid
// self-certifying owner identity for puzzle at difficulty d — that is, until
// MeetsPoW holds for its public key. It fans out across all CPUs and reports
// Progress to onProgress (may be nil) about ten times a second, and once more
// with the final tally when a key is found. Expected cost is ~2^d evaluations.
func MintSigningKey(puzzle Argon2idPuzzle, d Difficulty, onProgress func(Progress)) (SignKey, SignPubKey, error) {
	return MintSigningKeyContext(context.Background(), puzzle, d, onProgress)
}

// MintSigningKeyContext is MintSigningKey with cancellation: if ctx is cancelled
// before a key is found it returns ctx.Err(). A cancelled mint leaves nothing
// persisted — the caller simply gets no key.
func MintSigningKeyContext(ctx context.Context, puzzle Argon2idPuzzle, d Difficulty, onProgress func(Progress)) (SignKey, SignPubKey, error) {
	if puzzle.Memory == 0 {
		puzzle = DefaultArgon2id()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := max(runtime.NumCPU(), 1)

	type result struct {
		key SignKey
		pub SignPubKey
		err error
	}
	found := make(chan result, workers)
	var attempts atomic.Uint64
	start := time.Now()

	for range workers {
		go func() {
			for {
				if ctx.Err() != nil {
					return
				}
				key, pub, err := GenerateSigningKey()
				if err != nil {
					select {
					case found <- result{err: err}:
					case <-ctx.Done():
					}
					return
				}
				attempts.Add(1)
				if MeetsPoW(puzzle, pub[:], d) {
					select {
					case found <- result{key: key, pub: pub}:
					case <-ctx.Done():
					}
					return
				}
			}
		}()
	}

	// Progress reporter: a ticker independent of the workers so the display keeps
	// updating at a steady cadence regardless of per-attempt cost.
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		if onProgress == nil {
			return
		}
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				onProgress(Progress{Attempts: attempts.Load(), Elapsed: time.Since(start)})
			}
		}
	}()

	var res result
	select {
	case res = <-found:
	case <-ctx.Done():
		res = result{err: ctx.Err()}
	}
	cancel()
	<-progressDone

	if res.err != nil {
		return SignKey{}, SignPubKey{}, res.err
	}
	if onProgress != nil {
		onProgress(Progress{Attempts: attempts.Load(), Elapsed: time.Since(start)})
	}
	return res.key, res.pub, nil
}
