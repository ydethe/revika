package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/revika/revika/internal/crypto"
)

// loadOrCreateSigner loads the client's Ed25519 signing identity from the identities
// table, generating and persisting one on first run. The identity is what the sqlite
// rootstore's root pointers are signed and validated against.
func loadOrCreateSigner(database *sql.DB) (*crypto.Ed25519Signer, string, error) {
	var id string
	var private []byte
	err := database.QueryRow(`SELECT id, private_key FROM identities WHERE kind = 'signing' AND active = 1 LIMIT 1`).Scan(&id, &private)
	switch {
	case err == nil:
		signer, signerErr := crypto.NewEd25519Signer(private)
		if signerErr != nil {
			return nil, "", fmt.Errorf("load signing identity: %w", signerErr)
		}
		return signer, id, nil
	case errors.Is(err, sql.ErrNoRows):
		return createSigner(database)
	default:
		return nil, "", fmt.Errorf("query signing identity: %w", err)
	}
}

func createSigner(database *sql.DB) (*crypto.Ed25519Signer, string, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate signing identity: %w", err)
	}
	signer, err := crypto.NewEd25519Signer(private)
	if err != nil {
		return nil, "", fmt.Errorf("wrap signing identity: %w", err)
	}
	id, err := randomID()
	if err != nil {
		return nil, "", err
	}
	if _, err := database.Exec(
		`INSERT INTO identities(id, kind, public_key, private_key, algorithm, created_at_ns) VALUES (?, 'signing', ?, ?, 'ed25519', ?)`,
		id, []byte(public), []byte(private), time.Now().UnixNano(),
	); err != nil {
		return nil, "", fmt.Errorf("persist signing identity: %w", err)
	}
	return signer, id, nil
}

func randomID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate identity id: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
