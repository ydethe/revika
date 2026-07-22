# crypto

Client-side authenticated encryption for revika. Every object (chunk) is sealed
before any bytes leave a User's machine, so nodes only ever store ciphertext they
cannot read and cannot tamper with undetected.

## Purpose

Provides AES-256-GCM AEAD (authenticated encryption with associated data) using
only the Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`) — no
external crypto dependency. GCM gives both confidentiality and integrity: any
modification or truncation of the ciphertext causes decryption to fail.

## Exported API

### Constant

- `KeySize = 32` — the AES-256 key length in bytes (256 bits).

### Error

- `ErrDecrypt` — returned by `Open` when authentication fails (wrong key, or
  tampered/truncated ciphertext). By design it never reveals which cause.

### Type

- `Key [KeySize]byte` — a 256-bit symmetric key.

### Functions

- `NewKey() (Key, error)` — returns a fresh random key drawn from the OS CSPRNG
  (`crypto/rand`).
- `Seal(k Key, plaintext []byte) ([]byte, error)` — encrypts `plaintext` under
  `k`, returning `nonce || ciphertext || tag`.
- `Open(k Key, sealed []byte) ([]byte, error)` — reverses `Seal`, returning the
  plaintext or `ErrDecrypt`.

## Nonce handling

Each `Seal` call generates a fresh 12-byte random nonce (`GCM.NonceSize()`) from
the CSPRNG. The nonce is prepended to the output and the GCM authentication tag
is appended by `Seal`, so the wire format is `nonce(12) || ciphertext || tag(16)`.
`Open` splits the nonce prefix back off before verifying and decrypting.

Because the nonce is random per call, sealing identical plaintext twice yields
distinct outputs. No associated data is passed (the AAD argument is `nil`).

## Key sizes

- Key: 32 bytes (AES-256).
- Nonce: 12 bytes (GCM standard).
- Tag: 16 bytes (GCM authentication tag).

## How it fits into revika

revika encrypts everything client-side before shards leave the machine. Each
chunk is sealed under its own fresh `Key`, and the resulting ciphertext is what
gets erasure-coded and distributed to untrusted nodes — upholding the guiding
principle that nodes are dumb, untrusted blob stores trusted only for
availability, never confidentiality. Per-object keys are wrapped for sharing by
the `cap` package (ML-KEM-768); this package handles only the symmetric AEAD.

AES-256 is PQC-safe (a 256-bit key retains a ~128-bit security margin against
Grover's algorithm), so it satisfies revika's PQC-class crypto constraint using
stdlib primitives alone.
