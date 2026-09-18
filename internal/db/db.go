package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// migrations holds the ordered, numbered schema migrations. The migration
// version is the slice index plus one; each entry is applied exactly once and
// recorded in schema_migrations, so new migrations are appended, never edited.
var migrations = [][]string{
	// Migration 1: base schema (mirrors docs/Architecture.md §4.6).
	{
		`CREATE TABLE identities (
			id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('signing', 'kem', 'encryption')),
			public_key BLOB NOT NULL, private_key BLOB NOT NULL, algorithm TEXT NOT NULL,
			created_at_ns INTEGER NOT NULL,
			active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
		)`,
		`CREATE TABLE root_pointers (
			id INTEGER PRIMARY KEY CHECK (id = 1), owner_identity TEXT NOT NULL REFERENCES identities(id),
			sequence INTEGER NOT NULL CHECK (sequence >= 0), root_cap BLOB NOT NULL,
			signature BLOB NOT NULL, created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE items (
			id TEXT PRIMARY KEY, parent_id TEXT REFERENCES items(id) ON DELETE CASCADE,
			name TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('file', 'directory', 'symlink')),
			size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes >= 0), mode INTEGER,
			metadata_blob BLOB NOT NULL, content_version BLOB NOT NULL, metadata_version BLOB NOT NULL,
			manifest_id TEXT, created_at_ns INTEGER NOT NULL, modified_at_ns INTEGER NOT NULL,
			deleted_at_ns INTEGER,
			UNIQUE (parent_id, name)
		)`,
		`CREATE TABLE manifests (
			id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
			manifest_blob BLOB NOT NULL, content_hash BLOB NOT NULL UNIQUE, created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE chunks (
			id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL CHECK (ordinal >= 0), offset_bytes INTEGER NOT NULL CHECK (offset_bytes >= 0),
			plaintext_size INTEGER NOT NULL CHECK (plaintext_size >= 0),
			ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size >= 0),
			encryption_key BLOB NOT NULL, nonce BLOB NOT NULL, content_hash BLOB NOT NULL,
			UNIQUE (manifest_id, ordinal), UNIQUE (manifest_id, content_hash)
		)`,
		`CREATE TABLE providers (
			id TEXT PRIMARY KEY, kind TEXT NOT NULL, configuration BLOB NOT NULL, capabilities BLOB NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)), last_seen_ns INTEGER,
			health TEXT NOT NULL DEFAULT 'unknown'
				CHECK (health IN ('unknown', 'healthy', 'degraded', 'offline')),
			created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE shards (
			id TEXT PRIMARY KEY, chunk_id TEXT NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
			provider_id TEXT NOT NULL REFERENCES providers(id), shard_index INTEGER NOT NULL CHECK (shard_index >= 0),
			shard_kind TEXT NOT NULL CHECK (shard_kind IN ('data', 'parity')),
			size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0), content_hash BLOB NOT NULL,
			state TEXT NOT NULL DEFAULT 'pending'
				CHECK (state IN ('pending', 'available', 'missing', 'corrupt', 'deleted')),
			last_verified_ns INTEGER,
			UNIQUE (chunk_id, shard_index, provider_id)
		)`,
		`CREATE TABLE capabilities (
			id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
			issuer_identity TEXT NOT NULL REFERENCES identities(id), recipient_key BLOB,
			permissions INTEGER NOT NULL CHECK (permissions > 0), capability_blob BLOB NOT NULL,
			expires_at_ns INTEGER, revoked_at_ns INTEGER, created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE vector_clocks (
			item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE, actor_id TEXT NOT NULL,
			counter INTEGER NOT NULL CHECK (counter >= 0), PRIMARY KEY (item_id, actor_id)
		)`,
		`CREATE TABLE crdt_operations (
			id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
			actor_id TEXT NOT NULL, operation_blob BLOB NOT NULL, operation_hash BLOB NOT NULL UNIQUE,
			applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)), created_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE sync_anchors (
			id TEXT PRIMARY KEY, surface TEXT NOT NULL UNIQUE, sequence INTEGER NOT NULL CHECK (sequence >= 0),
			root_id TEXT NOT NULL, anchor_blob BLOB NOT NULL, updated_at_ns INTEGER NOT NULL
		)`,
		`CREATE TABLE repair_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			shard_id TEXT NOT NULL REFERENCES shards(id) ON DELETE CASCADE,
			provider_id TEXT REFERENCES providers(id),
			state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'completed', 'failed')),
			attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0), last_error TEXT,
			created_at_ns INTEGER NOT NULL, updated_at_ns INTEGER NOT NULL
		)`,
		`CREATE INDEX items_parent_idx ON items(parent_id)`,
		`CREATE INDEX chunks_manifest_idx ON chunks(manifest_id, ordinal)`,
		`CREATE INDEX shards_chunk_idx ON shards(chunk_id)`,
		`CREATE INDEX shards_provider_idx ON shards(provider_id, state)`,
		`CREATE INDEX capabilities_item_idx ON capabilities(item_id)`,
		`CREATE INDEX crdt_operations_item_idx ON crdt_operations(item_id, created_at_ns)`,
		`CREATE INDEX repair_jobs_state_idx ON repair_jobs(state, updated_at_ns)`,
	},
	// Migration 2: per-item content encryption keys for revika-client (kept local, never
	// sent to a store/adapter).
	{
		`CREATE TABLE file_keys (
			item_id TEXT PRIMARY KEY, encryption_key BLOB NOT NULL, created_at_ns INTEGER NOT NULL
		)`,
	},
}

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
	if _, err := database.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable sqlite foreign keys: %w", err)
	}
	if _, err := database.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	var current int
	if err := database.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read migration version: %w", err)
	}
	for index := current; index < len(migrations); index++ {
		version := index + 1
		if err := database.applyMigration(version, migrations[index]); err != nil {
			return err
		}
	}
	return nil
}

func (database *DB) applyMigration(version int, statements []string) error {
	transaction, err := database.Begin()
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", version, err)
	}
	for _, statement := range statements {
		if _, err := transaction.Exec(statement); err != nil {
			transaction.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
	}
	if _, err := transaction.Exec(`INSERT INTO schema_migrations(version) VALUES (?)`, version); err != nil {
		transaction.Rollback()
		return fmt.Errorf("record migration %d: %w", version, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", version, err)
	}
	return nil
}
