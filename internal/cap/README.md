# cap

revika's capability-delivery and identity layer. It wraps a serialized
read-capability (in practice, a file's manifest bytes) so that only the holder
of a chosen recipient's private key can unwrap it, and it provides the User's
Ed25519 signing identity used to prove shard ownership to nodes.

## Purpose

This is the mechanism behind sharing. Access to a file
is granted by handing over a *read-cap*; delivery is done by encrypting that cap
to the recipient's public key. Nodes are never involved and learn nothing —
wrapping and unwrapping are purely client-side. The package treats the cap as
opaque bytes, so the read-cap serialization can evolve independently.

## Capability wrapping (ML-KEM-768, `cap.go`)

Recipients are identified by an ML-KEM-768 keypair (NIST FIPS 203, the
post-quantum KEM formerly known as Kyber), from the `crypto/mlkem` standard
library.

`Wrap` is a **KEM-DEM** construction:

1. **KEM** — `Encapsulate` against the recipient's public (encapsulation) key
   yields a fresh random shared secret plus a KEM ciphertext.
2. **DEM** — that shared secret keys an AES-256-GCM seal of the payload (reused
   from `internal/crypto`; AES-256 is itself quantum-resistant).

The sealed output is `KEM ciphertext || AES-256-GCM ciphertext`. Every `Wrap`
draws fresh encapsulation randomness and a fresh GCM nonce, so the same
plaintext wrapped twice yields distinct outputs, and a wrapped cap carries no
sender identity and cannot be linked across shares. `Unwrap` decapsulates with
the recipient's private key to recover the same secret and open the DEM.

### Types and functions

- `PublicKey` — raw ML-KEM-768 encapsulation key (`PublicKeySize` = 1184 bytes);
  the recipient identity a sender wraps to. Safe to share.
- `PrivateKey` — 64-byte ML-KEM-768 seed (`PrivateKeySize`); the full
  decapsulation key is expanded from it on demand. Keep secret.
- `GenerateIdentity() (PrivateKey, PublicKey, error)` — fresh keypair from the OS
  CSPRNG.
- `Wrap(recipient PublicKey, plaintext []byte) ([]byte, error)` — seal to a
  recipient.
- `Unwrap(priv PrivateKey, pub PublicKey, sealed []byte) ([]byte, error)` — open
  a sealed cap, or return `ErrUnwrap`. `pub` is accepted for API symmetry but
  unused (decapsulation needs only the private key).
- `(PrivateKey).Public() (PublicKey, error)` — deterministically re-derive the
  matching public key.
- `String`, `ParsePublicKey`, `ParsePrivateKey` — standard-base64 text form used
  in files and on the CLI.
- `ErrUnwrap` — opaque failure for a wrong recipient key or tampered/truncated
  ciphertext (ML-KEM uses implicit rejection, so failure surfaces at the GCM
  authentication check; the cause is never distinguished, by design).

## Signing identity (Ed25519, `signing.go`)

A distinct Ed25519 keypair provides the User's *signing* identity. Where the
ML-KEM keys deliver confidentiality only (no sender identity), the signing key
proves *who* a request comes from. A User signs short authorization tokens with
it (see `internal/net`); a Node verifies those tokens to decide who owns a
shard, so only the signing-key holder can delete or renew what they stored. The
public key is the User's stable owner identity, independent of the ephemeral
libp2p peer identity of whatever host they dial from.

### Types and functions

- `SignKey` — Ed25519 private key (`SignKeySize` = 64 bytes, seed||public). Keep
  secret.
- `SignPubKey` — Ed25519 public key (`SignPubKeySize` = 32 bytes); the User's
  publishable owner identity, recorded by nodes as the shard owner.
- `SignatureSize` — 64 bytes, re-exported for fixed-width wire frames.
- `GenerateSigningKey() (SignKey, SignPubKey, error)` — fresh keypair from the OS
  CSPRNG.
- `(SignKey).Sign(msg []byte) []byte` — signature of `msg`.
- `(SignKey).Public() SignPubKey` — derive the matching public key.
- `(SignPubKey).Verify(msg, sig []byte) bool` — verify a signature.
- `String`, `ParseSignPubKey`, `ParseSignKey` — standard-base64 text form.

## Self-certifying owner identity (proof-of-work, `pow.go`)

Owner identities are self-minted for free, so ban-by-identity is only as strong
as the cost of minting a fresh one. `pow.go` raises that cost by making a valid
owner key **self-certifying**: its Ed25519 public key must, on its own, satisfy a
proof-of-work target. Minting means grinding fresh keypairs until one hashes
under the target — the public key *is* the proof, so it costs seconds-to-minutes
of CPU to produce yet **one hash to verify**, and the work is bound to that exact
key. A banned owner cannot re-mint a usable identity in milliseconds.

This is a **local** deterrent: difficulty and puzzle are operator policy, checked
statelessly by any node with no authority or consensus (matching revika's "each
node defends itself" model). It complements — does not replace — the deferred
economic/anti-Sybil layer: it is a re-mint speed bump, not a per-identity tax, so
it does not stop a patient attacker from pre-minting a stockpile.

The puzzle sits behind a small **`Puzzle` interface** so the hash is swappable:

- `SHA256Puzzle` — hashcash-style single SHA-256. Cheapest to verify, but a
  GPU/ASIC attacker grinds it far faster than an honest CPU.
- `Argon2idPuzzle{Time, Memory, Threads}` — memory-hard (Argon2id,
  `golang.org/x/crypto/argon2`). Every attempt costs a fixed slice of RAM+CPU, so
  the attacker's specialised-hardware edge collapses; both minting and
  verification pay one evaluation. `DefaultArgon2id()` = 64 MiB, 2 passes, 1 lane.

Difficulty is the number of leading zero bits the puzzle digest must have;
expected minting cost is `~2^Difficulty` evaluations, verification always one.
Hash-based PoW stays PQC-class: Grover only halves effective difficulty (a D-bit
proof costs ~`2^(D/2)` quantum evaluations) and memory-hardness blunts even that.

### Types and functions

- `Difficulty` — target as leading zero bits; `0` disables the check.
- `Puzzle` — `Name()` + `Sum(pubkey) []byte`; a deterministic digest of the key.
- `SHA256Puzzle`, `Argon2idPuzzle`, `DefaultArgon2id()`.
- `MeetsPoW(puzzle, pubkey, d) bool` — the verifier a node runs on a recovered
  owner pubkey; O(1) in the minter's attempt count.
- `MintSigningKey(puzzle, d, onProgress) (SignKey, SignPubKey, error)` — grind a
  self-certifying signing keypair, fanning out across all CPUs and reporting
  `Progress{Attempts, Elapsed}` to `onProgress` (may be nil) ~10×/s and once on
  success. `MintSigningKeyContext` adds cancellation.

`revika-ctl keygen` mints the signing key this way and renders an
ssh-keygen-style progress line (`-pow-puzzle`, `-pow-difficulty`). A node enforces
the other side: `net.Server.SetPoW` (wired by `revika-node -pow-difficulty`) runs
`MeetsPoW` on the owner pubkey recovered from a PUT's auth token and refuses the
write if it falls short. Since difficulty is per-node policy, a client must mint at
the highest difficulty among the nodes it uses under a matching puzzle; a
**difficulty advertisement** so `put` learns each node's requirement up front and
fails fast (instead of a late `ErrUnauthorized`) is planned — see
`internal/net/README.md` and Architecture.md §5.

## How it fits into revika

- **Sharing = wrapping keys, never copying plaintext.** A read-cap is wrapped
  with the recipient's ML-KEM-768 public key via `Wrap`; the recipient unwraps
  it with their private key. All crypto is PQC-class per the design constraints.
- **Ed25519 = storage owner identity.** The signing keypair authenticates
  ownership operations against nodes, keeping nodes as dumb, untrusted blob
  stores that only enforce who may mutate a shard.
