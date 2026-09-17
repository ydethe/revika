package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/klauspost/reedsolomon"
)

var ErrInsufficientShards = errors.New("pipeline: insufficient valid shards")

type ErasureProfile struct {
	DataShards   int
	ParityShards int
}

type ShardSet struct {
	Profile      ErasureProfile
	OriginalSize int
	Shards       [][]byte
	Digests      [][32]byte
}

func EncodeShards(ctx context.Context, data []byte, profile ErasureProfile) (ShardSet, error) {
	if err := validateProfile(profile); err != nil {
		return ShardSet{}, err
	}
	if err := contextError(ctx); err != nil {
		return ShardSet{}, err
	}
	coder, err := reedsolomon.New(profile.DataShards, profile.ParityShards)
	if err != nil {
		return ShardSet{}, err
	}
	shards, err := coder.Split(append([]byte(nil), data...))
	if err != nil {
		return ShardSet{}, err
	}
	if err := coder.Encode(shards); err != nil {
		return ShardSet{}, err
	}
	result := ShardSet{Profile: profile, OriginalSize: len(data), Shards: cloneShards(shards), Digests: make([][32]byte, len(shards))}
	for index, shard := range result.Shards {
		result.Digests[index] = sha256.Sum256(shard)
	}
	return result, nil
}

func (set ShardSet) Reconstruct(ctx context.Context, missing []bool) ([]byte, error) {
	if err := validateProfile(set.Profile); err != nil {
		return nil, err
	}
	if len(set.Shards) != set.Profile.DataShards+set.Profile.ParityShards || len(missing) != len(set.Shards) {
		return nil, ErrInsufficientShards
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	shards := cloneShards(set.Shards)
	available := 0
	for index, shard := range shards {
		if missing[index] {
			shards[index] = nil
			continue
		}
		if len(shard) == 0 || sha256.Sum256(shard) != set.Digests[index] {
			shards[index] = nil
			continue
		}
		available++
	}
	if available < set.Profile.DataShards {
		return nil, ErrInsufficientShards
	}
	coder, err := reedsolomon.New(set.Profile.DataShards, set.Profile.ParityShards)
	if err != nil {
		return nil, err
	}
	if err := coder.Reconstruct(shards); err != nil {
		return nil, ErrInsufficientShards
	}
	var output bytes.Buffer
	if err := coder.Join(&output, shards, set.OriginalSize); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func validateProfile(profile ErasureProfile) error {
	if profile.DataShards <= 0 || profile.ParityShards <= 0 {
		return errors.New("pipeline: data and parity shard counts must be positive")
	}
	return nil
}

func cloneShards(shards [][]byte) [][]byte {
	result := make([][]byte, len(shards))
	for index, shard := range shards {
		result[index] = append([]byte(nil), shard...)
	}
	return result
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

var _ io.Writer = (*bytes.Buffer)(nil)
