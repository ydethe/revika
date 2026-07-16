package chunk

import (
	"bytes"
	"math/rand"
	"testing"
)

func collect(t *testing.T, data []byte, size int) [][]byte {
	t.Helper()
	var chunks [][]byte
	for c, err := range Fixed(bytes.NewReader(data), size) {
		if err != nil {
			t.Fatalf("chunk error: %v", err)
		}
		chunks = append(chunks, c)
	}
	return chunks
}

func TestReassembly(t *testing.T) {
	const size = 64
	cases := []int{0, 1, 63, 64, 65, 127, 128, 129, 1000}
	for _, n := range cases {
		data := make([]byte, n)
		rand.New(rand.NewSource(int64(n))).Read(data)

		chunks := collect(t, data, size)

		var got bytes.Buffer
		for i, c := range chunks {
			// Every chunk but the last is exactly `size`.
			if i < len(chunks)-1 && len(c) != size {
				t.Fatalf("n=%d: interior chunk %d has len %d, want %d", n, i, len(c), size)
			}
			if len(c) > size {
				t.Fatalf("n=%d: chunk %d exceeds size: %d", n, i, len(c))
			}
			got.Write(c)
		}
		if !bytes.Equal(got.Bytes(), data) {
			t.Fatalf("n=%d: reassembly mismatch", n)
		}
	}
}

func TestChunkCount(t *testing.T) {
	// 130 bytes at size 64 → 64, 64, 2 → 3 chunks.
	chunks := collect(t, make([]byte, 130), 64)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if len(chunks[2]) != 2 {
		t.Fatalf("last chunk len = %d, want 2", len(chunks[2]))
	}
}

func TestEmptyReaderYieldsNoChunks(t *testing.T) {
	if chunks := collect(t, nil, 64); len(chunks) != 0 {
		t.Fatalf("empty reader produced %d chunks, want 0", len(chunks))
	}
}

func TestInvalidSize(t *testing.T) {
	var sawErr bool
	for _, err := range Fixed(bytes.NewReader([]byte("x")), 0) {
		if err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("size 0 should yield an error")
	}
}

func TestEarlyStop(t *testing.T) {
	// Breaking out of the range must not panic or leak.
	data := make([]byte, 1000)
	got := 0
	for c, err := range Fixed(bytes.NewReader(data), 64) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got += len(c)
		break
	}
	if got != 64 {
		t.Fatalf("consumed %d bytes before break, want 64", got)
	}
}
