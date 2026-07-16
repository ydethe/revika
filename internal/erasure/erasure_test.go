package erasure

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	p := Params{K: 4, M: 2}
	sizes := []int{0, 1, 7, 8, 9, 63, 64, 65, 1000, 1 << 16}
	for _, n := range sizes {
		data := randBytes(n, int64(n))
		shards, err := Encode(p, data)
		if err != nil {
			t.Fatalf("Encode(%d): %v", n, err)
		}
		if len(shards) != p.N() {
			t.Fatalf("Encode(%d): got %d shards, want %d", n, len(shards), p.N())
		}
		got, err := Decode(p, shards)
		if err != nil {
			t.Fatalf("Decode(%d): %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round trip mismatch at size %d", n)
		}
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	p := Params{K: 3, M: 2}
	data := randBytes(5000, 42)
	a, _ := Encode(p, data)
	b, _ := Encode(p, data)
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("shard %d differs between encodes; Encode must be deterministic", i)
		}
	}
}

// TestAnyKReconstruct is the core erasure property: any K of the N shards
// suffice, and fewer than K fail cleanly.
func TestAnyKReconstruct(t *testing.T) {
	p := Params{K: 4, M: 3} // N = 7
	data := randBytes(9001, 7)
	shards, err := Encode(p, data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	rng := rand.New(rand.NewSource(1))
	// Drop exactly M shards (random subsets): must still decode.
	for trial := 0; trial < 50; trial++ {
		damaged := cloneShards(shards)
		for _, idx := range pick(rng, p.N(), p.M) {
			damaged[idx] = nil
		}
		got, err := Decode(p, damaged)
		if err != nil {
			t.Fatalf("trial %d: dropped %d shards, decode failed: %v", trial, p.M, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("trial %d: reconstructed data mismatch", trial)
		}
	}

	// Drop M+1 shards: must fail (too few to reconstruct).
	for trial := 0; trial < 20; trial++ {
		damaged := cloneShards(shards)
		for _, idx := range pick(rng, p.N(), p.M+1) {
			damaged[idx] = nil
		}
		if _, err := Decode(p, damaged); err == nil {
			t.Fatalf("trial %d: dropping %d shards should fail but decode succeeded", trial, p.M+1)
		}
	}
}

func TestInvalidParams(t *testing.T) {
	for _, p := range []Params{{K: 0, M: 2}, {K: 3, M: 0}, {K: 200, M: 100}} {
		if _, err := Encode(p, []byte("x")); err == nil {
			t.Fatalf("Encode with invalid params %+v should fail", p)
		}
	}
}

func TestDecodeWrongShardCount(t *testing.T) {
	p := Params{K: 3, M: 2}
	shards, _ := Encode(p, []byte("hello"))
	if _, err := Decode(p, shards[:p.N()-1]); err == nil {
		t.Fatal("Decode with too few shard slots should fail")
	}
}

// helpers

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func cloneShards(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, s := range in {
		if s != nil {
			out[i] = bytes.Clone(s)
		}
	}
	return out
}

// pick returns count distinct indices in [0,n).
func pick(rng *rand.Rand, n, count int) []int {
	perm := rng.Perm(n)
	return perm[:count]
}
