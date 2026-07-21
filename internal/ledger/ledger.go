// Package ledger is a Node's per-node index of what it stores, for whom, and
// under what accounting. It is the "ledger" reserved in .gitignore — a local
// bookkeeping database, not a global blockchain.
//
// The blob store (internal/store) remains the source of truth for *bytes*; the
// ledger is the source of truth for *ownership and accounting*. It answers three
// questions the bare blob store cannot:
//
//   - Who owns a shard? A shard has a set of owner public keys (refcount by
//     owner). Content addressing dedups identical bytes, so several Users may
//     back one physical blob; each is charged and each may independently drop
//     their claim. The blob is only truly deletable once no owner remains.
//   - Is an owner over quota? Each owner is charged the full shard size on their
//     first claim, so PUT can be refused before accepting more bytes.
//   - What is collectible? Shards with no remaining owner (and, optionally,
//     shards whose leases have all expired) can be garbage-collected.
//
// Backend is SQLite via the pure-Go, cgo-free modernc.org/sqlite driver, keeping
// revika's build cgo-free.
package ledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"revika/internal/store"
)

// ErrQuotaExceeded is returned by AddOwner when recording a new claim would push
// the owner past its configured quota. No mutation happens in that case.
var ErrQuotaExceeded = errors.New("ledger: owner quota exceeded")

// ErrUnauthorized is returned by RemoveOwner when the caller is not an owner of
// the shard — the mechanism that stops one User deleting another's data.
var ErrUnauthorized = errors.New("ledger: caller does not own this shard")

// Options configures a Ledger.
type Options struct {
	// QuotaBytes caps the total bytes any single owner may hold. 0 = unlimited.
	QuotaBytes int64
	// LeaseTTL is how long a PUT's lease lasts before it is considered expired.
	// Expiry is advisory unless GC runs with expireLeases=true. 0 = no expiry.
	LeaseTTL time.Duration
}

// Ledger is a SQLite-backed ownership/lease/quota index. It is safe for
// concurrent use.
type Ledger struct {
	db   *sql.DB
	opts Options
}

const schema = `
CREATE TABLE IF NOT EXISTS shards (
	id      BLOB PRIMARY KEY,
	size    INTEGER NOT NULL,
	created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS owners (
	shard_id BLOB NOT NULL,
	owner    BLOB NOT NULL,
	put_at   INTEGER NOT NULL,
	expiry   INTEGER NOT NULL,
	PRIMARY KEY (shard_id, owner)
);
CREATE INDEX IF NOT EXISTS owners_by_owner ON owners(owner);
CREATE TABLE IF NOT EXISTS accounts (
	owner       BLOB PRIMARY KEY,
	bytes_used  INTEGER NOT NULL,
	shard_count INTEGER NOT NULL
);`

// Open opens (creating if needed) a ledger database at path. Pass ":memory:" for
// an ephemeral in-memory ledger (tests).
func Open(path string, opts Options) (*Ledger, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ledger: open %s: %w", path, err)
	}
	// SQLite tolerates a single writer; serialise access through one connection
	// so concurrent PUT/DELETE never hit "database is locked".
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: init schema: %w", err)
	}
	return &Ledger{db: db, opts: opts}, nil
}

// Close closes the underlying database.
func (l *Ledger) Close() error { return l.db.Close() }

// AddOwner records owner's claim on id (or renews its lease if already held) and
// enforces the quota. size is the shard's byte length.
//
// added is true only when this is a *new* claim by owner (so bytes are charged
// once); a re-PUT of already-owned bytes returns added=false and is a free
// renewal. If a new claim would exceed the owner's quota, AddOwner returns
// ErrQuotaExceeded and makes no change.
func (l *Ledger) AddOwner(id store.ShardID, owner []byte, size int64, now time.Time) (added bool, err error) {
	tx, err := l.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	expiry := int64(0)
	if l.opts.LeaseTTL > 0 {
		expiry = now.Add(l.opts.LeaseTTL).Unix()
	}

	// Already an owner? Renew the lease and return without charging again.
	var existing int
	if err := tx.QueryRow(`SELECT 1 FROM owners WHERE shard_id=? AND owner=?`, id[:], owner).Scan(&existing); err == nil {
		if _, err := tx.Exec(`UPDATE owners SET put_at=?, expiry=? WHERE shard_id=? AND owner=?`,
			now.Unix(), expiry, id[:], owner); err != nil {
			return false, err
		}
		return false, tx.Commit()
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	// New claim: enforce quota against the owner's current usage.
	if l.opts.QuotaBytes > 0 {
		var used int64
		if err := tx.QueryRow(`SELECT bytes_used FROM accounts WHERE owner=?`, owner).Scan(&used); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if used+size > l.opts.QuotaBytes {
			return false, ErrQuotaExceeded
		}
	}

	// Ensure the shard row exists (first owner records its size).
	if _, err := tx.Exec(`INSERT OR IGNORE INTO shards (id, size, created) VALUES (?, ?, ?)`,
		id[:], size, now.Unix()); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`INSERT INTO owners (shard_id, owner, put_at, expiry) VALUES (?, ?, ?, ?)`,
		id[:], owner, now.Unix(), expiry); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`
		INSERT INTO accounts (owner, bytes_used, shard_count) VALUES (?, ?, 1)
		ON CONFLICT(owner) DO UPDATE SET bytes_used = bytes_used + excluded.bytes_used, shard_count = shard_count + 1`,
		owner, size); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// RemoveOwner drops owner's claim on id and returns how many owners remain. It
// returns ErrUnauthorized (and makes no change) if owner never held id. When
// remaining is 0 the caller should delete the blob and then call DropRecord.
func (l *Ledger) RemoveOwner(id store.ShardID, owner []byte) (remaining int, err error) {
	tx, err := l.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var size int64
	err = tx.QueryRow(`SELECT s.size FROM owners o JOIN shards s ON s.id=o.shard_id WHERE o.shard_id=? AND o.owner=?`,
		id[:], owner).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrUnauthorized
	} else if err != nil {
		return 0, err
	}

	if _, err := tx.Exec(`DELETE FROM owners WHERE shard_id=? AND owner=?`, id[:], owner); err != nil {
		return 0, err
	}
	if err := chargeDown(tx, owner, size); err != nil {
		return 0, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM owners WHERE shard_id=?`, id[:]).Scan(&remaining); err != nil {
		return 0, err
	}
	return remaining, tx.Commit()
}

// DropRecord removes id's shard row and any remaining owner rows, crediting each
// affected owner's account. It is called after the physical blob is deleted (by
// DELETE when the last owner leaves), so the ledger no longer tracks a shard
// whose bytes are gone.
func (l *Ledger) DropRecord(id store.ShardID) error {
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	dropped, err := dropRecordTx(tx, id)
	if err != nil || !dropped {
		return err
	}
	return tx.Commit()
}

// CollectRecord atomically drops id's record, but only if it is still
// collectible — i.e. has no live owner (all owners gone, or, when expireLeases
// is set, all leases expired at now). It returns whether it dropped the record.
//
// GC calls this instead of DropRecord so that a PUT racing in between the
// collectibility snapshot and the drop (re-claiming the shard) is honoured: the
// re-claim leaves a live owner, CollectRecord returns false, and the shard —
// including its blob, which the racing PUT re-created — is retained.
func (l *Ledger) CollectRecord(id store.ShardID, now time.Time, expireLeases bool) (bool, error) {
	tx, err := l.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var live int
	if expireLeases {
		err = tx.QueryRow(`SELECT COUNT(*) FROM owners WHERE shard_id=? AND (expiry = 0 OR expiry >= ?)`,
			id[:], now.Unix()).Scan(&live)
	} else {
		err = tx.QueryRow(`SELECT COUNT(*) FROM owners WHERE shard_id=?`, id[:]).Scan(&live)
	}
	if err != nil {
		return false, err
	}
	if live > 0 {
		return false, nil // re-claimed since the snapshot; keep it
	}
	dropped, err := dropRecordTx(tx, id)
	if err != nil || !dropped {
		return false, err
	}
	return true, tx.Commit()
}

// dropRecordTx removes id's shard row and any owner rows within tx, crediting
// each owner's account. Returns false (no error) if the shard row was already
// gone. The caller commits.
func dropRecordTx(tx *sql.Tx, id store.ShardID) (bool, error) {
	var size int64
	err := tx.QueryRow(`SELECT size FROM shards WHERE id=?`, id[:]).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // already gone
	} else if err != nil {
		return false, err
	}

	// Credit back every remaining owner before removing their rows.
	rows, err := tx.Query(`SELECT owner FROM owners WHERE shard_id=?`, id[:])
	if err != nil {
		return false, err
	}
	var owners [][]byte
	for rows.Next() {
		var o []byte
		if err := rows.Scan(&o); err != nil {
			rows.Close()
			return false, err
		}
		owners = append(owners, o)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	for _, o := range owners {
		if err := chargeDown(tx, o, size); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM owners WHERE shard_id=?`, id[:]); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM shards WHERE id=?`, id[:]); err != nil {
		return false, err
	}
	return true, nil
}

// chargeDown debits an owner's account by size (one shard). It removes the
// account row once it reaches zero so empty owners don't accumulate.
func chargeDown(tx *sql.Tx, owner []byte, size int64) error {
	if _, err := tx.Exec(`UPDATE accounts SET bytes_used = bytes_used - ?, shard_count = shard_count - 1 WHERE owner=?`,
		size, owner); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM accounts WHERE owner=? AND shard_count <= 0`, owner)
	return err
}

// Collectible returns the IDs of shards eligible for garbage collection: those
// with no remaining owner. If expireLeases is true it also returns shards whose
// every owner's lease has expired at now (owners with expiry 0 never expire).
func (l *Ledger) Collectible(now time.Time, expireLeases bool) ([]store.ShardID, error) {
	var q string
	var args []any
	if expireLeases {
		// A shard is collectible unless it has at least one *live* owner: an owner
		// with no expiry (0) or an expiry still in the future.
		q = `SELECT id FROM shards WHERE id NOT IN (
			SELECT shard_id FROM owners WHERE expiry = 0 OR expiry >= ?)`
		args = []any{now.Unix()}
	} else {
		q = `SELECT id FROM shards WHERE id NOT IN (SELECT shard_id FROM owners)`
	}
	rows, err := l.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIDs(rows)
}

// Account reports an owner's current usage.
func (l *Ledger) Account(owner []byte) (bytesUsed int64, shardCount int, err error) {
	err = l.db.QueryRow(`SELECT bytes_used, shard_count FROM accounts WHERE owner=?`, owner).
		Scan(&bytesUsed, &shardCount)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	return bytesUsed, shardCount, err
}

// ReconcileReport summarises what a Reconcile pass found and did.
type ReconcileReport struct {
	OrphanBlobs    int // blobs on disk with no ledger record (retained)
	DroppedRecords int // ledger records whose blob is gone (dropped)
}

// Reconcile aligns the ledger with the blobs actually on disk, which are the
// source of truth for bytes. It is meant to run at startup:
//
//   - A blob present on disk but absent from the ledger (an orphan) is RETAINED,
//     not deleted — it may be a pre-ledger blob or a crash between blob-write and
//     ledger-commit. It is only reported; GC can reclaim genuinely abandoned
//     blobs later.
//   - A ledger record whose blob is gone (bytes lost) has its record dropped and
//     the owners' accounts credited back.
//   - Account totals are recomputed from the surviving owner/shard rows so
//     accounting cannot drift permanently.
func (l *Ledger) Reconcile(ctx context.Context, blobs store.Store) (ReconcileReport, error) {
	var rep ReconcileReport

	lister, ok := blobs.(store.Lister)
	if !ok {
		return rep, fmt.Errorf("ledger: reconcile needs an enumerable store (store.Lister)")
	}
	diskIDs, err := lister.List(ctx)
	if err != nil {
		return rep, fmt.Errorf("ledger: reconcile list: %w", err)
	}
	onDisk := make(map[store.ShardID]bool, len(diskIDs))
	for _, id := range diskIDs {
		onDisk[id] = true
	}

	// Ledger records whose blob is gone: drop them.
	rows, err := l.db.QueryContext(ctx, `SELECT id FROM shards`)
	if err != nil {
		return rep, err
	}
	ledgerIDs, err := scanIDs(rows)
	rows.Close()
	if err != nil {
		return rep, err
	}
	inLedger := make(map[store.ShardID]bool, len(ledgerIDs))
	for _, id := range ledgerIDs {
		inLedger[id] = true
		if !onDisk[id] {
			if err := l.DropRecord(id); err != nil {
				return rep, err
			}
			rep.DroppedRecords++
		}
	}

	// Orphan blobs: on disk but unknown to the ledger. Retain and report.
	for _, id := range diskIDs {
		if !inLedger[id] {
			rep.OrphanBlobs++
		}
	}

	if err := l.recomputeAccounts(ctx); err != nil {
		return rep, err
	}
	return rep, nil
}

// recomputeAccounts rebuilds the accounts table from the current owner/shard
// rows, so per-owner totals stay consistent after drops.
func (l *Ledger) recomputeAccounts(ctx context.Context) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM accounts`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO accounts (owner, bytes_used, shard_count)
		SELECT o.owner, COALESCE(SUM(s.size), 0), COUNT(*)
		FROM owners o JOIN shards s ON s.id = o.shard_id
		GROUP BY o.owner`); err != nil {
		return err
	}
	return tx.Commit()
}

// scanIDs reads a result set of single BLOB id columns into ShardIDs.
func scanIDs(rows *sql.Rows) ([]store.ShardID, error) {
	var ids []store.ShardID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(raw) != len(store.ShardID{}) {
			return nil, fmt.Errorf("ledger: shard id column is %d bytes, want %d", len(raw), len(store.ShardID{}))
		}
		var id store.ShardID
		copy(id[:], raw)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
