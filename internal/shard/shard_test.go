package shard

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/revika/revika/pkg/model"
)

func TestNewShardSplitterValidation(t *testing.T) {
	tests := []struct {
		name    string
		k       int
		m       int
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default",
			k:       3,
			m:       2,
			wantErr: false,
		},
		{
			name:    "valid k=1",
			k:       1,
			m:       0,
			wantErr: false,
		},
		{
			name:    "k <= 0",
			k:       0,
			m:       2,
			wantErr: true,
			errMsg:  "k (data shards) must be > 0",
		},
		{
			name:    "m < 0",
			k:       3,
			m:       -1,
			wantErr: true,
			errMsg:  "m (parity shards) must be >= 0",
		},
		{
			name:    "k+m > 256",
			k:       200,
			m:       100,
			wantErr: true,
			errMsg:  "k+m must be <= 256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewShardSplitter(tt.k, tt.m)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewShardSplitter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Fatalf("expected error %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestShardSplitterRoundtrip(t *testing.T) {
	tests := []struct {
		name     string
		k        int
		m        int
		fileSize int
	}{
		{
			name:     "small file k=3 m=2",
			k:        3,
			m:        2,
			fileSize: 100,
		},
		{
			name:     "medium file k=3 m=2",
			k:        3,
			m:        2,
			fileSize: 10 * 1024, // 10KB
		},
		{
			name:     "1MB file k=3 m=2",
			k:        3,
			m:        2,
			fileSize: 1024 * 1024,
		},
		{
			name:     "minimal k=1 m=0",
			k:        1,
			m:        0,
			fileSize: 100,
		},
		{
			name:     "high redundancy k=2 m=5",
			k:        2,
			m:        5,
			fileSize: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			originalFile := make([]byte, tt.fileSize)
			rand.Read(originalFile)

			// Split file
			splitter, err := NewShardSplitter(tt.k, tt.m)
			if err != nil {
				t.Fatalf("NewShardSplitter failed: %v", err)
			}

			shards, err := splitter.SplitFile(originalFile)
			if err != nil {
				t.Fatalf("SplitFile failed: %v", err)
			}

			// Verify we have k+m shards
			if len(shards) != tt.k+tt.m {
				t.Fatalf("expected %d shards, got %d", tt.k+tt.m, len(shards))
			}

			// Reconstruct with exactly k shards (the minimum)
			reconstructor := NewShardReconstructor()

			// Use first k shards
			selectedShards := shards[:tt.k]
			reconstructed, err := reconstructor.ReconstructFile(selectedShards, tt.k, tt.m, int64(tt.fileSize))
			if err != nil {
				t.Fatalf("ReconstructFile failed: %v", err)
			}

			// Verify reconstruction matches (should be exact size after automatic trimming)
			if len(reconstructed) != tt.fileSize {
				t.Fatalf("reconstructed size mismatch: got %d, want %d", len(reconstructed), tt.fileSize)
			}

			if !bytes.Equal(reconstructed, originalFile) {
				t.Fatal("reconstructed file does not match original")
			}
		})
	}
}

func TestShardSplitterEmptyFile(t *testing.T) {
	splitter := NewShardSplitterDefault()
	_, err := splitter.SplitFile([]byte{})
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if err.Error() != "file bytes cannot be empty" {
		t.Fatalf("expected 'file bytes cannot be empty', got %q", err.Error())
	}
}

func TestShardParityResilience(t *testing.T) {
	// Test that we can lose m shards and still reconstruct
	originalFile := make([]byte, 5000)
	rand.Read(originalFile)

	splitter := NewShardSplitterDefault() // k=3, m=2
	shards, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	reconstructor := NewShardReconstructor()

	tests := []struct {
		name           string
		loseShardCount int
	}{
		{name: "lose 0 shards", loseShardCount: 0},
		{name: "lose 1 shard", loseShardCount: 1},
		{name: "lose 2 shards (all parity)", loseShardCount: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Select k shards by removing loseShardCount shards from the end
			selectedShards := shards[:len(shards)-tt.loseShardCount]
			if len(selectedShards) < 3 {
				t.Skip("not enough shards after loss")
			}

			reconstructed, err := reconstructor.ReconstructFile(selectedShards, 3, 2, int64(len(originalFile)))
			if err != nil {
				t.Fatalf("ReconstructFile failed: %v", err)
			}

			if !bytes.Equal(reconstructed, originalFile) {
				t.Fatal("reconstructed file does not match original")
			}
		})
	}
}

func TestShardReconstructorWithAllShards(t *testing.T) {
	// Verify we can reconstruct with all k+m shards
	originalFile := make([]byte, 3000)
	rand.Read(originalFile)

	splitter := NewShardSplitterDefault()
	shards, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	reconstructor := NewShardReconstructor()

	// Use all shards
	reconstructed, err := reconstructor.ReconstructFile(shards, 3, 2, int64(len(originalFile)))
	if err != nil {
		t.Fatalf("ReconstructFile with all shards failed: %v", err)
	}

	if !bytes.Equal(reconstructed, originalFile) {
		t.Fatal("reconstructed with all shards does not match original")
	}
}

func TestShardReconstructorErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		k       int
		wantErr bool
		errMsg  string
	}{
		{
			name:    "k <= 0",
			k:       0,
			wantErr: true,
			errMsg:  "invalid k value: 0",
		},
		{
			name:    "negative k",
			k:       -1,
			wantErr: true,
			errMsg:  "invalid k value: -1",
		},
	}

	reconstructor := NewShardReconstructor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reconstructor.ReconstructFile(nil, tt.k, 2, 0)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReconstructFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Fatalf("expected error %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestReconstructFileInsufficientShards(t *testing.T) {
	reconstructor := NewShardReconstructor()

	// Try to reconstruct with only 2 shards (less than required k=3)
	shards := []model.ShardInfo{
		{ID: "shard1", Bytes: make([]byte, 100), Index: 0},
		{ID: "shard2", Bytes: make([]byte, 100), Index: 1},
	}

	_, err := reconstructor.ReconstructFile(shards, 3, 2, 0)
	if err == nil {
		t.Fatal("expected error when shards < k")
	}
	if err.Error() != "need at least 3 shards, got 2" {
		t.Fatalf("expected 'need at least 3 shards', got %q", err.Error())
	}
}

func TestReconstructFileNoShards(t *testing.T) {
	reconstructor := NewShardReconstructor()

	_, err := reconstructor.ReconstructFile([]model.ShardInfo{}, 3, 2, 0)
	if err == nil {
		t.Fatal("expected error with no shards")
	}
	if err.Error() != "need at least 3 shards, got 0" {
		t.Fatalf("expected 'need at least 3 shards', got %q", err.Error())
	}
}

func TestReconstructFileMismatchedShardLength(t *testing.T) {
	reconstructor := NewShardReconstructor()

	shards := []model.ShardInfo{
		{ID: "shard1", Bytes: make([]byte, 100), Index: 0},
		{ID: "shard2", Bytes: make([]byte, 50), Index: 1}, // Different length!
		{ID: "shard3", Bytes: make([]byte, 100), Index: 2},
	}

	_, err := reconstructor.ReconstructFile(shards, 3, 2, 0)
	if err == nil {
		t.Fatal("expected error with mismatched shard lengths")
	}
}

func TestVerifyShardID(t *testing.T) {
	splitter := NewShardSplitterDefault()
	originalFile := make([]byte, 1000)
	rand.Read(originalFile)

	shards, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	// Verify all shards have correct IDs
	for i, shard := range shards {
		if !VerifyShardID(shard) {
			t.Fatalf("shard %d ID verification failed", i)
		}
	}

	// Corrupt a shard and verify ID check fails
	corruptedShard := shards[0]
	corruptedShard.ID = "invalid-id"
	if VerifyShardID(corruptedShard) {
		t.Fatal("corrupted shard should fail ID verification")
	}
}

func TestVerifyShardIntegrity(t *testing.T) {
	data := []byte("test data for integrity check")
	hash1 := VerifyShardIntegrity(data)

	// Same data should produce same hash
	hash2 := VerifyShardIntegrity(data)
	if hash1 != hash2 {
		t.Fatal("same data should produce same hash")
	}

	// Different data should produce different hash
	data2 := []byte("different data")
	hash3 := VerifyShardIntegrity(data2)
	if hash1 == hash3 {
		t.Fatal("different data should produce different hash")
	}
}

func TestShardSplitterNonDeterminism(t *testing.T) {
	// Test that splitting same file produces different shard bytes due to random nonce in encryption
	// (Although this package doesn't do encryption, the IDs should be different each time due to how they're computed)
	// Actually, if we split the same plaintext, we get the same shards (same Reed-Solomon output)
	// This is expected and correct for deterministic splitting

	originalFile := make([]byte, 1000)
	rand.Read(originalFile)

	splitter := NewShardSplitterDefault()

	shards1, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	shards2, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	// Both splits should be identical (deterministic Reed-Solomon)
	if len(shards1) != len(shards2) {
		t.Fatal("should have same number of shards")
	}

	for i := range shards1 {
		if !bytes.Equal(shards1[i].Bytes, shards2[i].Bytes) {
			t.Fatal("same input should produce same shards (deterministic)")
		}
		if shards1[i].ID != shards2[i].ID {
			t.Fatal("same shards should have same ID")
		}
	}
}

func TestShardIndexTracking(t *testing.T) {
	originalFile := make([]byte, 2000)
	rand.Read(originalFile)

	splitter := NewShardSplitterDefault()
	shards, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	// Verify indices are sequential
	for i, shard := range shards {
		if shard.Index != i {
			t.Fatalf("shard %d has wrong index: expected %d, got %d", i, i, shard.Index)
		}
	}

	// Verify reconstruction works with shards in different order
	reconstructor := NewShardReconstructor()

	// Shuffle first k shards but keep indices
	shuffledShards := []model.ShardInfo{
		shards[1],
		shards[0],
		shards[2],
	}

	reconstructed, err := reconstructor.ReconstructFile(shuffledShards, 3, 2, int64(len(originalFile)))
	if err != nil {
		t.Fatalf("ReconstructFile with shuffled shards failed: %v", err)
	}

	if !bytes.Equal(reconstructed[:len(originalFile)], originalFile) {
		t.Fatal("reconstruction with shuffled shards failed")
	}
}

func TestNewShardSplitterDefault(t *testing.T) {
	splitter := NewShardSplitterDefault()

	originalFile := make([]byte, 1000)
	rand.Read(originalFile)

	shards, err := splitter.SplitFile(originalFile)
	if err != nil {
		t.Fatalf("SplitFile failed: %v", err)
	}

	// Should have default k=3, m=2
	if len(shards) != 5 {
		t.Fatalf("expected 5 shards (k=3, m=2), got %d", len(shards))
	}

	reconstructor := NewShardReconstructor()
	reconstructed, err := reconstructor.ReconstructFile(shards[:DefaultK], DefaultK, DefaultM, int64(len(originalFile)))
	if err != nil {
		t.Fatalf("ReconstructFile failed: %v", err)
	}

	if !bytes.Equal(reconstructed[:len(originalFile)], originalFile) {
		t.Fatal("default splitter roundtrip failed")
	}
}

// BenchmarkShardSplit benchmarks splitting a 10MB file
func BenchmarkShardSplit(b *testing.B) {
	splitter := NewShardSplitterDefault()
	fileData := make([]byte, 10*1024*1024) // 10MB
	rand.Read(fileData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := splitter.SplitFile(fileData)
		if err != nil {
			b.Fatalf("SplitFile failed: %v", err)
		}
	}
}

// BenchmarkShardReconstruct benchmarks reconstructing from 3 shards
func BenchmarkShardReconstruct(b *testing.B) {
	splitter := NewShardSplitterDefault()
	fileData := make([]byte, 10*1024*1024) // 10MB
	rand.Read(fileData)

	shards, err := splitter.SplitFile(fileData)
	if err != nil {
		b.Fatalf("SplitFile failed: %v", err)
	}

	reconstructor := NewShardReconstructor()
	selectedShards := shards[:3]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := reconstructor.ReconstructFile(selectedShards, 3, 2, int64(len(fileData)))
		if err != nil {
			b.Fatalf("ReconstructFile failed: %v", err)
		}
	}
}
