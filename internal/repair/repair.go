package repair

import (
	"context"
	"errors"

	"github.com/revika/revika/internal/pipeline"
)

var ErrInvalidRepair = errors.New("repair: invalid shard repair request")

type Target interface {
	Put(ctx context.Context, objectID string, shard []byte) error
}

type Job struct {
	ObjectID string
	Index    int
	Target   Target
}

func RepairMissing(ctx context.Context, set pipeline.ShardSet, missing []bool, jobs []Job) error {
	if len(missing) != len(set.Shards) || len(jobs) == 0 {
		return ErrInvalidRepair
	}
	rebuilt, err := Rebuild(ctx, set, missing)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.Index < 0 || job.Index >= len(rebuilt) || !missing[job.Index] || job.Target == nil {
			return ErrInvalidRepair
		}
		if err := job.Target.Put(ctx, job.ObjectID, rebuilt[job.Index]); err != nil {
			return err
		}
	}
	return nil
}

func Rebuild(ctx context.Context, set pipeline.ShardSet, missing []bool) ([][]byte, error) {
	data, err := set.Reconstruct(ctx, missing)
	if err != nil {
		return nil, err
	}
	rebuilt, err := pipeline.EncodeShards(ctx, data, set.Profile)
	if err != nil {
		return nil, err
	}
	return rebuilt.Shards, nil
}
