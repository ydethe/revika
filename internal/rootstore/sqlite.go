package rootstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SQLite is a Store backed by the client's local sqlite database (root_pointers table, a
// single row keyed by id = 1). It relies on the caller having configured the database with
// SetMaxOpenConns(1) (as internal/db.Open does): that serializes transactions on the single
// connection, which is what makes the read-current-then-write sequence below race-free
// without additional locking.
type SQLite struct {
	db         *sql.DB
	identityID string
	owner      []byte
}

func NewSQLite(database *sql.DB, identityID string, owner []byte) *SQLite {
	return &SQLite{db: database, identityID: identityID, owner: append([]byte(nil), owner...)}
}

func (s *SQLite) Load(ctx context.Context) (RootPointer, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RootPointer{}, false, err
	}
	var sequence uint64
	var root, signature []byte
	var timestamp int64
	err := s.db.QueryRowContext(ctx, `SELECT sequence, root_cap, signature, created_at_ns FROM root_pointers WHERE id = 1`).
		Scan(&sequence, &root, &signature, &timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return RootPointer{}, false, nil
	}
	if err != nil {
		return RootPointer{}, false, fmt.Errorf("rootstore: read root pointer: %w", err)
	}
	pointer := RootPointer{Owner: append([]byte(nil), s.owner...), Sequence: sequence, Timestamp: timestamp, Root: root, Signature: signature}
	if err := Validate(pointer, s.owner); err != nil {
		return RootPointer{}, false, err
	}
	return pointer, true, nil
}

func (s *SQLite) Save(ctx context.Context, pointer RootPointer) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := Validate(pointer, s.owner); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rootstore: begin save: %w", err)
	}
	defer tx.Rollback()
	var current uint64
	err = tx.QueryRowContext(ctx, `SELECT sequence FROM root_pointers WHERE id = 1`).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("rootstore: read current sequence: %w", err)
	default:
		if pointer.Sequence <= current {
			return ErrRollback
		}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO root_pointers(id, owner_identity, sequence, root_cap, signature, created_at_ns)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			owner_identity = excluded.owner_identity, sequence = excluded.sequence,
			root_cap = excluded.root_cap, signature = excluded.signature, created_at_ns = excluded.created_at_ns
	`, s.identityID, pointer.Sequence, pointer.Root, pointer.Signature, pointer.Timestamp)
	if err != nil {
		return fmt.Errorf("rootstore: write root pointer: %w", err)
	}
	return tx.Commit()
}

var _ Store = (*SQLite)(nil)
