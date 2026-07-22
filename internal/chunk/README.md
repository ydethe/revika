# chunk

Package `chunk` splits a byte stream into chunks. Chunking is the **first stage
of the store pipeline**:

```
chunk → encrypt → erasure-code → distribute
```

Each chunk is independently encrypted and erasure-coded, so chunk boundaries
determine the unit of deduplication and of incremental re-upload.

## Purpose

The current implementation is **fixed-size**: every chunk is exactly `Size`
bytes except the last, which holds the remainder.

Content-defined chunking (CDC) — a rolling hash so that an edit only rewrites
the affected chunk — is a **planned upgrade** that can replace `Fixed` behind
the same iterator contract.

## Exported API

### `const DefaultSize`

```go
const DefaultSize = 4 << 20 // 4 MiB
```

A reasonable starting chunk size.

### `func Fixed`

```go
func Fixed(r io.Reader, size int) iter.Seq2[[]byte, error]
```

Returns an iterator (Go 1.23+ `iter.Seq2`) over fixed-size chunks of `r`.

Behavior:

- Each yielded slice is freshly allocated and owned by the caller.
- Iteration stops after the first error; that error is yielded with a `nil`
  chunk.
- An empty reader yields no chunks.
- A clean end on a chunk boundary yields nothing extra.
- A short final chunk is yielded with its actual length.
- A non-positive `size` yields a single error.

## Usage

```go
for c, err := range chunk.Fixed(r, chunk.DefaultSize) {
    if err != nil {
        return err
    }
    // encrypt + erasure-code c ...
}
```

## Fit in revika

Chunking is where a file first becomes a sequence of independent units on the
User side. Downstream stages (`internal/crypto`, `internal/erasure`) operate on
these chunks, and the resulting shards are content-addressed and distributed to
nodes. Because chunk boundaries drive dedup and incremental re-upload, the
chunking strategy directly affects storage and bandwidth efficiency — the
motivation for the planned CDC upgrade.
