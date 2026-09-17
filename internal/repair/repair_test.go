package repair

import (
	"context"
	"testing"

	"github.com/revika/revika/internal/pipeline"
)

func TestRepairMissingRegeneratesCiphertextShards(t *testing.T) {
	set, err := pipeline.EncodeShards(context.Background(), []byte("ciphertext payload"), pipeline.ErasureProfile{DataShards: 3, ParityShards: 2})
	if err != nil {
		t.Fatal(err)
	}
	missing := []bool{true, false, false, false, true}
	left := &target{data: make(map[string][]byte)}
	if err := RepairMissing(context.Background(), set, missing, []Job{{ObjectID: "chunk", Index: 0, Target: left}, {ObjectID: "chunk", Index: 4, Target: left}}); err != nil {
		t.Fatal(err)
	}
	if len(left.data) != 2 {
		t.Fatalf("repaired shard count = %d, want 2", len(left.data))
	}
}

type target struct {
	data map[string][]byte
}

func (target *target) Put(_ context.Context, objectID string, shard []byte) error {
	target.data[objectID+string(rune(len(target.data)))] = append([]byte(nil), shard...)
	return nil
}
