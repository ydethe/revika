package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
)

func TestChunkBytesRespectsBoundsAndDigests(t *testing.T) {
	config := ChunkConfig{MinSize: 8, AverageSize: 16, MaxSize: 32, WindowSize: 8}
	input := bytes.Repeat([]byte("revika"), 40)
	chunks, err := ChunkBytes(context.Background(), input, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) == 0 {
		t.Fatal("ChunkBytes returned no chunks")
	}
	for index, chunk := range chunks {
		if len(chunk.Data) > config.MaxSize {
			t.Fatalf("chunk %d has size %d > max %d", index, len(chunk.Data), config.MaxSize)
		}
		if got := chunk.Digest; got != digest(chunk.Data) {
			t.Fatalf("chunk %d has an incorrect digest", index)
		}
	}
	var rebuilt []byte
	for _, chunk := range chunks {
		rebuilt = append(rebuilt, chunk.Data...)
	}
	if !bytes.Equal(rebuilt, input) {
		t.Fatal("chunks do not reconstruct the input")
	}
}

func TestChunkBytesHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ChunkBytes(ctx, bytes.Repeat([]byte("x"), 1024), DefaultChunkConfig())
	if err == nil {
		t.Fatal("ChunkBytes returned nil error for cancelled context")
	}
}

func digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}
