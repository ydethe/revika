package compress

import (
    "bytes"
    "testing"
)

func TestRoundTrip(t *testing.T) {
    cases := map[string][]byte{
        "empty":        {},
        "small":        []byte("hello revika"),
        "repetitive":   bytes.Repeat([]byte("revika "), 1000),
        "binary-zeros": make([]byte, 4096),
    }
    for name, in := range cases {
        packed, err := Compress(in)
        if err != nil {
            t.Fatalf("[%s] Compress: %v", name, err)
        }
        out, err := Decompress(packed)
        if err != nil {
            t.Fatalf("[%s] Decompress: %v", name, err)
        }
        if !bytes.Equal(out, in) {
            t.Fatalf("[%s] round trip mismatch: got %d bytes, want %d", name, len(out), len(in))
        }
    }
}

func TestCompressShrinksRepetitiveData(t *testing.T) {
    in := bytes.Repeat([]byte("revika "), 1000)
    packed, err := Compress(in)
    if err != nil {
        t.Fatalf("Compress: %v", err)
    }
    if len(packed) >= len(in) {
        t.Fatalf("expected compression to shrink data: %d >= %d", len(packed), len(in))
    }
}
