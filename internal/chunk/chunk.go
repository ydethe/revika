// Package chunk splits a byte stream into chunks. Chunking is the first stage
// of the store pipeline: each chunk is independently encrypted and
// erasure-coded, so chunk boundaries determine the unit of dedup and of
// incremental re-upload.
//
// This implementation is fixed-size: every chunk is exactly Size bytes except
// the last, which holds the remainder. Content-defined chunking (a rolling
// hash, so an edit only rewrites the affected chunk) is a planned upgrade that
// can replace Fixed behind the same iterator contract.
package chunk

import (
	"fmt"
	"io"
	"iter"
)

// DefaultSize is a reasonable starting chunk size (4 MiB).
const DefaultSize = 4 << 20

// Fixed returns an iterator over fixed-size chunks of r. Each yielded slice is
// freshly allocated and owned by the caller. Iteration stops after the first
// error; that error is yielded with a nil chunk. An empty reader yields no
// chunks. A non-positive size yields a single error.
func Fixed(r io.Reader, size int) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		if size <= 0 {
			yield(nil, fmt.Errorf("chunk: size must be positive, got %d", size))
			return
		}
		for {
			buf := make([]byte, size)
			n, err := io.ReadFull(r, buf)
			switch {
			case err == nil:
				if !yield(buf, nil) {
					return
				}
			case err == io.ErrUnexpectedEOF:
				// Final short chunk.
				yield(buf[:n], nil)
				return
			case err == io.EOF:
				// Clean end on a chunk boundary; nothing more to yield.
				return
			default:
				yield(nil, fmt.Errorf("chunk: read: %w", err))
				return
			}
		}
	}
}
