// Package compress is the pipeline's optional pre-encryption compression stage.
//
// Ordering matters: compression must run on plaintext, *before* encryption.
// Ciphertext is high-entropy and effectively incompressible, so compress-then-
// encrypt is the only ordering that saves space. The pipeline decides per chunk
// whether to keep the compressed form (see storeChunk), so a chunk of already-
// compressed or otherwise incompressible data is stored verbatim rather than
// expanded.
//
// The codec is DEFLATE (compress/flate): standard library, pure Go, no cgo —
// consistent with revika's crypto-from-stdlib policy. It lives behind these two
// functions so it can be swapped for zstd later without touching the pipeline.
package compress

import (
    "bytes"
    "compress/flate"
    "io"
)

// Compress returns the DEFLATE-compressed form of data.
func Compress(data []byte) ([]byte, error) {
    var buf bytes.Buffer
    w, err := flate.NewWriter(&buf, flate.DefaultCompression)
    if err != nil {
        return nil, err
    }
    if _, err := w.Write(data); err != nil {
        return nil, err
    }
    if err := w.Close(); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

// Decompress reverses Compress, returning the original bytes.
func Decompress(data []byte) ([]byte, error) {
    r := flate.NewReader(bytes.NewReader(data))
    defer r.Close()
    out, err := io.ReadAll(r)
    if err != nil {
        return nil, err
    }
    return out, nil
}
