# compress

The pipeline's optional **pre-encryption compression** stage.

## Why it exists

Compression only saves space when it runs on plaintext. Ciphertext produced by
AES-256-GCM is high-entropy and effectively incompressible, so the only useful
ordering is **compress → encrypt**. This package provides that stage; the
pipeline runs it on each plaintext chunk before `crypto.Seal`.

## Codec

DEFLATE via the standard library `compress/flate` at `DefaultCompression`. This
keeps revika pure Go / cgo-free and consistent with its crypto-from-stdlib
policy. The codec is deliberately hidden behind two functions so it can be
swapped for zstd later without touching the pipeline.

## Exported functions

- **`Compress(data []byte) ([]byte, error)`** — DEFLATE-compress `data`.
- **`Decompress(data []byte) ([]byte, error)`** — reverse `Compress`.

## Per-chunk decision (in the pipeline)

`Compress` can *expand* incompressible input (already-compressed files, random
data). The pipeline therefore compresses a chunk, keeps the result only when it
is smaller than the original, and records the outcome in `ChunkRef.Compressed`.
`LoadFile` decompresses a chunk iff that flag is set — so the choice is made per
chunk at store time, not globally.

## Security note

Compress-then-encrypt leaks information about plaintext content through
ciphertext length (the CRIME/BREACH class of attack) when an attacker can
influence part of the content. This is an accepted trade-off for at-rest file
storage; revisit it if chunk contents ever mix attacker-controlled and secret
data.
