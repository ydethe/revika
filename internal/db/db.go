package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

type DB struct {
	*sql.DB
}

func Open(path string) (*DB, error) {
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	database.SetMaxOpenConns(1)
	result := &DB{DB: database}
	if err := result.migrate(); err != nil {
		database.Close()
		return nil, err
	}
	return result, nil
}

func (database *DB) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS identities (
			id TEXT PRIMARY KEY, kind TEXT NOT NULL, public_key BLOB NOT NULL,
			private_key BLOB NOT NULL, algorithm TEXT NOT NULL, created_at_ns INTEGER NOT NULL,
			active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
		)`,
		`CREATE TABLE IF NOT EXISTS root_pointers (
			id INTEGER PRIMARY KEY CHECK (id = 1), owner_identity TEXT NOT NULL REFERENCES identities(id),
			sequence INTEGER NOT NULL CHECK (sequence >= 0), root_cap BLOB NOT NULL,
			signature BLOB NOT NULL, created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS items (
			id TEXT PRIMARY KEY, parent_id TEXT REFERENCES items(id) ON DELETE CASCADE,
			name TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('file', 'directory', 'symlink')),
			size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes >= 0), metadata_blob BLOB NOT NULL,
			content_version BLOB NOT NULL, metadata_version BLOB NOT NULL, manifest_id TEXT,
			created_at_ns INTEGER NOT NULL, modified_at_ns INTEGER NOT NULL,
			UNIQUE (parent_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS manifests (
			id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
			manifest_blob BLOB NOT NULL, content_hash BLOB NOT NULL UNIQUE, created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS capabilities (
			id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
			issuer_identity TEXT NOT NULL REFERENCES identities(id), recipient_key BLOB,
			permissions INTEGER NOT NULL CHECK (permissions > 0), capability_blob BLOB NOT NULL,
			expires_at_ns INTEGER, revoked_at_ns INTEGER, created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS vector_clocks (
			item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE, actor_id TEXT NOT NULL,
			counter INTEGER NOT NULL CHECK (counter >= 0), PRIMARY KEY (item_id, actor_id)
		)`,
		`CREATE TABLE IF NOT EXISTS crdt_operations (
			id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
			actor_id TEXT NOT NULL, operation_blob BLOB NOT NULL, operation_hash BLOB NOT NULL UNIQUE,
			applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)), created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sync_anchors (
			id TEXT PRIMARY KEY, surface TEXT NOT NULL UNIQUE, sequence INTEGER NOT NULL CHECK (sequence >= 0),
			root_id TEXT NOT NULL, anchor_blob BLOB NOT NULL, updated_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS repair_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT, shard_id TEXT NOT NULL, provider_id TEXT,
			state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'completed', 'failed')),
			attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0), last_error TEXT,
			created_at_ns INTEGER NOT NULL, updated_at_ns INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS items_parent_idx ON items(parent_id)`,
		`CREATE INDEX IF NOT EXISTS capabilities_item_idx ON capabilities(item_id)`,
		`CREATE INDEX IF NOT EXISTS crdt_operations_item_idx ON crdt_operations(item_id, created_at_ns)`,
		`CREATE INDEX IF NOT EXISTS repair_jobs_state_idx ON repair_jobs(state, updated_at_ns)`,
	}
	if _, err := database.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable sqlite foreign keys: %w", err)
	}
	transaction, err := database.Begin()
	if err != nil {
		return fmt.Errorf("begin database migration: %w", err)
	}
	for _, statement := range statements {
		if _, err := transaction.Exec(statement); err != nil {
			transaction.Rollback()
			return fmt.Errorf("apply database migration: %w", err)
		}
	}
	if _, err := transaction.Exec(`INSERT OR IGNORE INTO schema_migrations(version) VALUES (?)`, schemaVersion); err != nil {
		transaction.Rollback()
		return fmt.Errorf("record database migration: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit database migration: %w", err)
	}
	return nil
}
