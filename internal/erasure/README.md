# erasure

Reed–Solomon erasure coding for revika, built on
[`klauspost/reedsolomon`](https://github.com/klauspost/reedsolomon).

## Purpose

The package splits a blob into `K` data shards plus `M` parity shards such that
**any `K` of the `K+M` shards reconstruct the original** — "RAID-5/6 over the
internet". revika erasure-codes the *encrypted* bytes of each chunk, so shards
are opaque ciphertext fragments that individual nodes can store without ever
seeing plaintext.

This is redundancy by erasure coding rather than replication: `K` data + `M`
parity shards, any `K` reconstruct. The revika default is `k=4`, `m=2` (chosen
at the call site, not hard-coded here).

## Model

- A payload is split into `N = K + M` equal-length shards.
- The first `K` shards are data; the remaining `M` are parity.
- Losing any `M` shards is survivable; losing more is not.

## Exported API

- **`Params`** — selects the code rate. Fields `K` (data shards, `>= 1`) and
  `M` (parity shards, `>= 1`). Both must be positive and `K+M <= 256`.
- **`Params.N() int`** — total shard count, `K + M`.
- **`Encode(p Params, data []byte) ([][]byte, error)`** — splits `data` into
  `p.N()` equal-length shards (first `p.K` data, rest parity). Prepends an
  8-byte big-endian length header to the payload before splitting so the exact
  original length can be recovered on decode.
- **`Decode(p Params, shards [][]byte) ([]byte, error)`** — reconstructs the
  original data. `shards` must have length `p.N()`, with missing shards passed
  as `nil` entries. Succeeds when at least `p.K` shards are present, otherwise
  returns an error. Strips the length header and returns the exact original
  bytes.

## Determinism (why it matters for repair)

`Encode` is deterministic: the same input always produces byte-identical
shards. The repair layer depends on this. Because shards are addressed by
content hash, regenerating a lost shard from surviving ones reproduces its
**exact content address** — so repair works on ciphertext alone (no decryption
key) and manifests never need rewriting after a repair.

## Framing detail

Reed–Solomon operates on fixed, equal-sized shards and zero-pads the final one.
To recover the precise original length, `Encode` prepends an 8-byte big-endian
`uint64` length header; `Decode` reads it back and trims trailing padding.

## Fit within revika

Erasure coding sits in the User-side storage pipeline after chunking and
encryption: each encrypted chunk is passed through `Encode`, and the resulting
shards are distributed across independent nodes (see `internal/pipeline`,
`internal/stripe`, and `internal/net`). On retrieval, the pipeline collects any
`K` available shards and calls `Decode`. The `internal/repair` package uses the
same deterministic `Encode` to regenerate lost shards.
