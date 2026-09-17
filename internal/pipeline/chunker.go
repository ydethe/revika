package pipeline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
)

type ChunkConfig struct {
	MinSize     int
	AverageSize int
	MaxSize     int
	WindowSize  int
}

func DefaultChunkConfig() ChunkConfig {
	return ChunkConfig{MinSize: 16 * 1024, AverageSize: 64 * 1024, MaxSize: 256 * 1024, WindowSize: 64}
}

type Chunk struct {
	Offset int64
	Data   []byte
	Digest [32]byte
}

func ChunkBytes(ctx context.Context, input []byte, config ChunkConfig) ([]Chunk, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, nil
	}

	mask := uint64(config.AverageSize - 1)
	chunks := make([]Chunk, 0, len(input)/config.AverageSize+1)
	start := 0
	for position := 0; position < len(input); position++ {
		if position%4096 == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		size := position - start + 1
		boundary := size >= config.MinSize && (rollingHash(input, position, config.WindowSize)&mask) == 0
		if size >= config.MaxSize || boundary {
			chunks = appendChunk(chunks, input[start:position+1], int64(start))
			start = position + 1
		}
	}
	if start < len(input) {
		chunks = appendChunk(chunks, input[start:], int64(start))
	}
	return chunks, nil
}

func appendChunk(chunks []Chunk, data []byte, offset int64) []Chunk {
	copyData := append([]byte(nil), data...)
	return append(chunks, Chunk{Offset: offset, Data: copyData, Digest: sha256.Sum256(copyData)})
}

func (config ChunkConfig) validate() error {
	if config.MinSize <= 0 || config.AverageSize <= config.MinSize || config.MaxSize < config.AverageSize {
		return errors.New("pipeline: invalid chunk size configuration")
	}
	if config.AverageSize&(config.AverageSize-1) != 0 {
		return errors.New("pipeline: average chunk size must be a power of two")
	}
	if config.WindowSize <= 0 {
		return errors.New("pipeline: window size must be positive")
	}
	return nil
}

func rollingHash(input []byte, end, windowSize int) uint64 {
	start := end - windowSize + 1
	if start < 0 {
		start = 0
	}
	var hash uint64 = 14695981039346656037
	for _, value := range input[start : end+1] {
		hash ^= uint64(value)
		hash *= 1099511628211
	}
	return hash
}

func (c ChunkConfig) String() string {
	return fmt.Sprintf("min=%d average=%d max=%d window=%d", c.MinSize, c.AverageSize, c.MaxSize, c.WindowSize)
}
