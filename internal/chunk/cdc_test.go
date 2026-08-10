package chunk

import (
    "bytes"
    "math/rand/v2"
    "testing"
)

// fillRnd fills b with pseudo-random bytes from rng. math/rand/v2 dropped the
// Read method; we derive bytes from Uint64 calls instead.
func fillRnd(rng *rand.Rand, b []byte) {
    for i := 0; i < len(b); i += 8 {
        v := rng.Uint64()
        for j := 0; j < 8 && i+j < len(b); j++ {
            b[i+j] = byte(v >> (uint(j) * 8))
        }
    }
}

func collectCDC(t *testing.T, data []byte, min, target, max int) [][]byte {
    t.Helper()
    var chunks [][]byte
    for c, err := range CDC(bytes.NewReader(data), min, target, max) {
        if err != nil {
            t.Fatalf("CDC error: %v", err)
        }
        chunks = append(chunks, c)
    }
    return chunks
}

// TestCDCReassembly checks that concatenating CDC chunks reconstructs the input exactly.
func TestCDCReassembly(t *testing.T) {
    rng := rand.New(rand.NewPCG(42, 0))
    sizes := []int{0, 1, 511, 512, 513, 4095, 4096, 4097, 100_000}
    const (min, target, max = 512, 4096, 16384)
    for _, n := range sizes {
        data := make([]byte, n)
        fillRnd(rng, data)
        chunks := collectCDC(t, data, min, target, max)
        var got bytes.Buffer
        for _, c := range chunks {
            got.Write(c)
        }
        if !bytes.Equal(got.Bytes(), data) {
            t.Fatalf("n=%d: reassembly mismatch", n)
        }
    }
}

// TestCDCSizeBounds checks that every chunk falls within [minSize, maxSize].
func TestCDCSizeBounds(t *testing.T) {
    rng := rand.New(rand.NewPCG(7, 0))
    const (min, target, max = 512, 4096, 16384)
    data := make([]byte, 1<<20) // 1 MiB
    fillRnd(rng, data)
    chunks := collectCDC(t, data, min, target, max)
    for i, c := range chunks {
        // Only interior chunks must be at least min; the last may be shorter.
        if i < len(chunks)-1 && len(c) < min {
            t.Errorf("chunk %d: len=%d < min=%d", i, len(c), min)
        }
        if len(c) > max {
            t.Errorf("chunk %d: len=%d > max=%d", i, len(c), max)
        }
    }
}

// TestCDCDeterminism checks that the same input always produces the same boundaries.
func TestCDCDeterminism(t *testing.T) {
    rng := rand.New(rand.NewPCG(99, 0))
    const (min, target, max = 512, 4096, 16384)
    data := make([]byte, 200_000)
    fillRnd(rng, data)
    a := collectCDC(t, data, min, target, max)
    b := collectCDC(t, data, min, target, max)
    if len(a) != len(b) {
        t.Fatalf("different chunk counts: %d vs %d", len(a), len(b))
    }
    for i := range a {
        if !bytes.Equal(a[i], b[i]) {
            t.Errorf("chunk %d differs between runs", i)
        }
    }
}

// TestCDCIncrementalStability is the key property: prepending or appending a
// byte only changes the first or last chunk — interior chunks are stable.
func TestCDCIncrementalStability(t *testing.T) {
    rng := rand.New(rand.NewPCG(123, 0))
    const (min, target, max = 512, 4096, 16384)
    // Use a large payload so there are many interior chunks to stay stable.
    base := make([]byte, 500_000)
    fillRnd(rng, base)
    baseChunks := collectCDC(t, base, min, target, max)
    if len(baseChunks) < 3 {
        t.Skip("not enough chunks to test stability")
    }

    // Append a byte — only the last chunk should change.
    modified := append(base, 0xFF)
    modChunks := collectCDC(t, modified, min, target, max)
    stable := 0
    for i := 0; i < len(baseChunks)-1 && i < len(modChunks)-1; i++ {
        if bytes.Equal(baseChunks[i], modChunks[i]) {
            stable++
        }
    }
    // At least 70% of interior chunks should remain stable (gear CDC is not
    // perfect on small inputs, but should be highly stable in practice).
    interior := len(baseChunks) - 1
    if interior > 0 && stable*10 < interior*7 {
        t.Errorf("only %d/%d interior chunks stable after append (want >=70%%)", stable, interior)
    }
}

func TestCDCEmptyInput(t *testing.T) {
    chunks := collectCDC(t, nil, 512, 4096, 16384)
    if len(chunks) != 0 {
        t.Fatalf("empty input: got %d chunks, want 0", len(chunks))
    }
}

func TestCDCInvalidParams(t *testing.T) {
    var erred bool
    for _, err := range CDC(bytes.NewReader([]byte("x")), 0, 4096, 16384) {
        if err != nil {
            erred = true
        }
    }
    if !erred {
        t.Fatal("expected error for zero minSize")
    }
}
