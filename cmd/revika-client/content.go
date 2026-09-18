package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/revika/revika/internal/pipeline"
	"github.com/revika/revika/internal/provider"
)

var errInvalidEnvelope = errors.New("revika-client: invalid encrypted content envelope")

// encryptContent seals plaintext under a fresh per-file key (AES-256-GCM via
// internal/pipeline) and returns the on-namespace envelope (version + nonce + ciphertext,
// none of it secret) alongside the key, which the caller must keep local (sqlite
// file_keys) and never pass to the store/adapter.
func encryptContent(plaintext []byte) (envelope, key []byte, err error) {
	key, err = pipeline.GenerateEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	chunk, err := pipeline.EncryptChunk(key, plaintext, nil)
	if err != nil {
		return nil, nil, err
	}
	envelope = make([]byte, 0, 3+len(chunk.Nonce)+len(chunk.Ciphertext))
	envelope = append(envelope, chunk.Version)
	var nonceLen [2]byte
	binary.BigEndian.PutUint16(nonceLen[:], uint16(len(chunk.Nonce)))
	envelope = append(envelope, nonceLen[:]...)
	envelope = append(envelope, chunk.Nonce...)
	envelope = append(envelope, chunk.Ciphertext...)
	return envelope, key, nil
}

func decryptContent(key, envelope []byte) ([]byte, error) {
	if len(envelope) < 3 {
		return nil, errInvalidEnvelope
	}
	version := envelope[0]
	nonceLen := int(binary.BigEndian.Uint16(envelope[1:3]))
	if len(envelope) < 3+nonceLen {
		return nil, errInvalidEnvelope
	}
	nonce := envelope[3 : 3+nonceLen]
	ciphertext := envelope[3+nonceLen:]
	return pipeline.DecryptChunk(key, pipeline.EncryptedChunk{Version: version, Nonce: nonce, Ciphertext: ciphertext}, nil)
}

func putFileKey(database *sql.DB, id provider.ItemID, key []byte) error {
	_, err := database.Exec(
		`INSERT INTO file_keys(item_id, encryption_key, created_at_ns) VALUES (?, ?, ?)
		 ON CONFLICT(item_id) DO UPDATE SET encryption_key = excluded.encryption_key, created_at_ns = excluded.created_at_ns`,
		string(id), key, time.Now().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("revika-client: save file key: %w", err)
	}
	return nil
}

func getFileKey(database *sql.DB, id provider.ItemID) ([]byte, error) {
	var key []byte
	err := database.QueryRow(`SELECT encryption_key FROM file_keys WHERE item_id = ?`, string(id)).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("revika-client: no encryption key stored locally for %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("revika-client: load file key: %w", err)
	}
	return key, nil
}

func deleteFileKeys(database *sql.DB, ids []provider.ItemID) error {
	for _, id := range ids {
		if _, err := database.Exec(`DELETE FROM file_keys WHERE item_id = ?`, string(id)); err != nil {
			return fmt.Errorf("revika-client: delete file key: %w", err)
		}
	}
	return nil
}
