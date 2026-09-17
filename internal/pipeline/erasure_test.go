package pipeline

import (
	"bytes"
	"context"
	"testing"
)

func TestErasureReconstructsAfterShardLoss(t *testing.T) {
	input := bytes.Repeat([]byte("resilient data"), 100)
	set, err := EncodeShards(context.Background(), input, ErasureProfile{DataShards: 4, ParityShards: 2})
	if err != nil {
		t.Fatal(err)
	}
	missing := []bool{true, false, false, true, false, false}
	got, err := set.Reconstruct(context.Background(), missing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("reconstructed data differs from input")
	}
}

func TestErasureRejectsCorruptionBeyondParity(t *testing.T) {
	set, err := EncodeShards(context.Background(), []byte("small payload"), ErasureProfile{DataShards: 3, ParityShards: 1})
	if err != nil {
		t.Fatal(err)
	}
	set.Shards[0][0] ^= 1
	set.Shards[1][0] ^= 1
	missing := []bool{false, false, false, false}
	if _, err := set.Reconstruct(context.Background(), missing); err != ErrInsufficientShards {
		t.Fatalf("corruption error = %v, want ErrInsufficientShards", err)
	}
}
