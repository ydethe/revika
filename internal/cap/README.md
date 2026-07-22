# cap

revika's capability-delivery and identity layer. It wraps a serialized
read-capability (in practice, a file's manifest bytes) so that only the holder
of a chosen recipient's private key can unwrap it, and it provides the User's
Ed25519 signing identity used to prove shard ownership to nodes.

## Purpose

This is the mechanism behind sharing in the Tahoe-LAFS model. Access to a file
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

## How it fits into revika

- **Sharing = wrapping keys, never copying plaintext.** A read-cap is wrapped
  with the recipient's ML-KEM-768 public key via `Wrap`; the recipient unwraps
  it with their private key. All crypto is PQC-class per the design constraints.
- **Ed25519 = storage owner identity.** The signing keypair authenticates
  ownership operations against nodes, keeping nodes as dumb, untrusted blob
  stores that only enforce who may mutate a shard.
