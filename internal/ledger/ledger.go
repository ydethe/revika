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
//
// Defence controls (security/Defence.md; primitives P13, P10 in security/frameworks.md):
//
//	SC-6 (Resource Availability)            — per-owner quotas + leases bound storage per owner. Compl. AC-3.
//	SC-5 (Denial-of-Service Protection)     — the byte quota caps how much one owner can store.
//	AU-9 (Protection of Audit Information)   — partial: Reconcile/recomputeAccounts give structural
//	     integrity, but rows are not signed or append-only (see Defence.md notes).
package ledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

	// QuotaRamp is Axis B: it graduates a new owner's *effective* quota from a
	// small initial fraction (QuotaInitialFraction) of QuotaBytes at age zero up to
	// the full QuotaBytes over this duration, measured from the owner's first
	// recorded claim. A brand-new identity therefore starts nearly powerless, so
	// minting a fresh one to evade a ban buys little write capacity — capability is
	// earned by age, which a Sybil cannot fake. 0 = no ramp: the full quota applies
	// immediately (prior behaviour). Has no effect unless QuotaBytes > 0.
	QuotaRamp time.Duration
	// QuotaInitialFraction is the fraction (0,1) of QuotaBytes a brand-new owner may
	// use at age zero, ramping linearly to the full quota over QuotaRamp. A value
	// <=0 or >=1 disables the ramp (full quota immediately). Ignored when QuotaRamp
	// is 0. An owner's very first shard is always admitted regardless (bounded by
	// the wire's max shard size) so it can record its first_seen timestamp and begin
	// accruing standing.
	QuotaInitialFraction float64
}

// Ledger is a SQLite-backed ownership/lease/quota index. It is safe for
// concurrent use.
type Ledger struct {
	db   *sql.DB
	opts Options
}

// schemaVersion is the ledger schema version this binary targets. It is
// stored in SQLite's PRAGMA user_version after every migration so Open can
// detect whether it needs to migrate and whether the database was written by a
// newer binary (in which case it refuses to open and tells the operator to
// upgrade). Bump this constant whenever a new migration is added.
const schemaVersion = 1

// schemaV0 is the original table layout (created with IF NOT EXISTS so it is
// safe to run against a database that already has some or all of these tables
// from a pre-migration-tracking release). It intentionally omits first_seen
// from accounts; migration 0→1 adds it as an ALTER TABLE so the migration
// list stays authoritative and no column appears in two places.
const schemaV0 = `
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
);
CREATE TABLE IF NOT EXISTS stripes (
	shard_id BLOB PRIMARY KEY REFERENCES shards(id) ON DELETE CASCADE,
	k        INTEGER NOT NULL,
	m        INTEGER NOT NULL,
	siblings BLOB NOT NULL,
	grant    BLOB NOT NULL
);`

// ledgerMigrations is the ordered list of forward migrations. Each entry
// migrates the schema from (index) to (index+1). A new migration is appended
// here and schemaVersion is bumped by one. Migrations run inside a single
// transaction that also advances user_version, so a crash mid-migration leaves
// the database at the previous version and Open retries the migration on the
// next start.
var ledgerMigrations = []func(*sql.Tx) error{
	// Migration 0 → 1: create the base tables (idempotent via IF NOT EXISTS for
	// databases from pre-migration releases) and add the first_seen column used
	// by the Axis B age-graduated quota (Architecture §5). Pre-migration databases
	// may already have the column; the column-exists check makes the ALTER a no-op
	// in that case so existing owners retain their full quota (first_seen=0 =
	// maximum age) rather than being throttled as freshly minted identities.
	func(tx *sql.Tx) error {
		if _, err := tx.Exec(schemaV0); err != nil {
			return fmt.Errorf("create base tables: %w", err)
		}
		// Check whether first_seen already exists (pre-migration database).
		var count int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name='first_seen'`,
		).Scan(&count); err != nil {
			return fmt.Errorf("check first_seen column: %w", err)
		}
		if count == 0 {
			if _, err := tx.Exec(
				`ALTER TABLE accounts ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0`,
			); err != nil {
				return fmt.Errorf("add first_seen: %w", err)
			}
		}
		return nil
	},
}

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
	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: %w", err)
	}
	return &Ledger{db: db, opts: opts}, nil
}

// migrateSchema reads PRAGMA user_version and runs any pending migrations up to
// schemaVersion. Each migration runs in its own transaction that also advances
// user_version, so a mid-migration crash leaves the database at the version
// before the failed migration and Open retries from that point on the next start.
func migrateSchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > schemaVersion {
		return fmt.Errorf("schema version %d is newer than this binary (max supported: %d); upgrade revika-node", version, schemaVersion)
	}
	for version < schemaVersion {
		next := version + 1
		migrate := ledgerMigrations[version]
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("migrate %d→%d: begin: %w", version, next, err)
		}
		if err := migrate(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate %d→%d: %w", version, next, err)
		}
		// Advance user_version inside the transaction so the migration and its
		// version stamp are atomic. SQLite PRAGMA cannot use bound parameters, so
		// we use Sprintf with a validated integer.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, next)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate %d→%d: set version: %w", version, next, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate %d→%d: commit: %w", version, next, err)
		}
		version = next
	}
	return nil
}

// Close closes the underlying database.
func (l *Ledger) Close() error { return l.db.Close() }

// QuotaBytes returns the configured per-owner quota in bytes (0 = unlimited).
func (l *Ledger) QuotaBytes() int64 { return l.opts.QuotaBytes }

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

	// New claim: enforce quota against the owner's current usage and its
	// age-graduated *effective* quota (Axis B). A brand-new owner (no account row)
	// always lands its first shard — bounded by the wire's max shard size — so it
	// can record first_seen and begin accruing standing; only its second and later
	// claims are held to the ramping effective quota.
	if l.opts.QuotaBytes > 0 {
		var (
			used      int64
			firstSeen int64
		)
		err := tx.QueryRow(`SELECT bytes_used, first_seen FROM accounts WHERE owner=?`, owner).Scan(&used, &firstSeen)
		if errors.Is(err, sql.ErrNoRows) {
			// Brand-new owner: no account yet. first_seen is set to now on insert
			// below; the used==0 path admits this first shard unconditionally.
			used, firstSeen = 0, now.Unix()
		} else if err != nil {
			return false, err
		}
		if used > 0 && used+size > effectiveQuota(l.opts, firstSeen, now) {
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
		INSERT INTO accounts (owner, bytes_used, shard_count, first_seen) VALUES (?, ?, 1, ?)
		ON CONFLICT(owner) DO UPDATE SET bytes_used = bytes_used + excluded.bytes_used, shard_count = shard_count + 1`,
		owner, size, now.Unix()); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// effectiveQuota returns the byte cap in force for an owner first seen at
// firstSeenUnix, evaluated at now (Axis B). With no ramp configured (QuotaRamp <= 0
// or an out-of-range QuotaInitialFraction) it is the full QuotaBytes. Otherwise it
// rises linearly from QuotaInitialFraction*QuotaBytes at age zero to the full quota
// once the owner's age reaches QuotaRamp, and stays there. Pure arithmetic on the
// first_seen already read for the quota check, so it adds no query to the write
// path.
func effectiveQuota(opts Options, firstSeenUnix int64, now time.Time) int64 {
	full := opts.QuotaBytes
	if opts.QuotaRamp <= 0 {
		return full
	}
	frac := opts.QuotaInitialFraction
	if frac <= 0 || frac >= 1 {
		return full // ramp disabled by an out-of-range fraction
	}
	age := now.Sub(time.Unix(firstSeenUnix, 0))
	if age >= opts.QuotaRamp {
		return full
	}
	age = max(age, 0)
	ratio := frac + (1-frac)*(float64(age)/float64(opts.QuotaRamp))
	return max(int64(float64(full)*ratio), 1)
}

// RenewLease extends the lease expiry for an existing owner claim on id. It
// returns ErrUnauthorized when owner does not currently hold id (the caller
// never owned or has already dropped it). When the ledger has no LeaseTTL
// configured (TTL == 0), the lease has no expiry and RenewLease is a no-op.
func (l *Ledger) RenewLease(id store.ShardID, owner []byte, now time.Time) error {
	if l.opts.LeaseTTL == 0 {
		return nil // no expiry configured; leases are perpetual
	}
	expiry := now.Add(l.opts.LeaseTTL).Unix()
	res, err := l.db.Exec(
		`UPDATE owners SET put_at=?, expiry=? WHERE shard_id=? AND owner=?`,
		now.Unix(), expiry, id[:], owner,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUnauthorized
	}
	return nil
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

// OwnerStat is one owner's (client's) accounting: the raw owner public key and
// how much it holds. Owner is the exact bytes stored in the ledger; callers
// render it (hex/base64) as they see fit.
type OwnerStat struct {
	Owner      []byte
	BytesUsed  int64
	ShardCount int
}

// Stats is an aggregate snapshot of what a node currently stores, for the
// metrics/status surface. Shards and BytesUsed count *physical* storage (each
// content-addressed blob once, regardless of how many owners share it), while
// per-owner BytesUsed is what each owner is charged (so their sum can exceed the
// physical total when owners dedup onto the same blobs).
type Stats struct {
	Shards    int64       // distinct shards stored
	BytesUsed int64       // physical bytes across all shards
	Clients   int         // distinct owners storing shards
	Owners    []OwnerStat // per-owner breakdown, largest first
}

// Stats returns an aggregate snapshot of the ledger for reporting.
func (l *Ledger) Stats() (Stats, error) {
	var s Stats
	if err := l.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM shards`).
		Scan(&s.Shards, &s.BytesUsed); err != nil {
		return Stats{}, err
	}
	rows, err := l.db.Query(`SELECT owner, bytes_used, shard_count FROM accounts ORDER BY bytes_used DESC, owner`)
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var o OwnerStat
		if err := rows.Scan(&o.Owner, &o.BytesUsed, &o.ShardCount); err != nil {
			return Stats{}, err
		}
		s.Owners = append(s.Owners, o)
	}
	if err := rows.Err(); err != nil {
		return Stats{}, err
	}
	s.Clients = len(s.Owners)
	return s, nil
}

// DefaultEntryLimit caps a single ledger browse page when the caller passes a
// non-positive Limit, so a browser never tries to render the whole ledger at once.
const DefaultEntryLimit = 100

// LedgerFilter narrows an Entries browse query (the /admin ledger browser). Empty
// fields match everything, so a zero-value filter browses the whole ledger. Limit
// <= 0 falls back to DefaultEntryLimit; a negative Offset is treated as 0.
type LedgerFilter struct {
	// ShardHexPrefix matches shards whose content hash, rendered as hex, starts with
	// this (case-insensitive) prefix. LIKE metacharacters in it are escaped, so it is
	// a literal prefix, not a pattern.
	ShardHexPrefix string
	// Owner, when non-empty, restricts the result to shards this exact owner public
	// key currently claims.
	Owner  []byte
	Limit  int
	Offset int
}

// LedgerEntry is one shard as the ledger browser presents it: the content-addressed
// shard ID, its physical size and first-recorded time, how many owners currently
// claim it, and — when a stripe (erasure) row exists — the K/M parameters and the
// sibling shard count. K, M and Siblings are meaningful only when HasStripe is true.
type LedgerEntry struct {
	ShardID    store.ShardID
	Size       int64
	Created    int64 // unix seconds the shard row was first recorded
	OwnerCount int
	HasStripe  bool
	K, M       int
	Siblings   int
}

// EntriesResult is one page of a ledger browse plus Total, the number of rows
// matching the filter before Limit/Offset are applied, so the caller can paginate.
type EntriesResult struct {
	Entries []LedgerEntry
	Total   int
	Limit   int
	Offset  int
}

// Entries browses the shard rows matching f, newest-recorded first, joining the
// per-shard owner count and (when present) the erasure stripe context. It backs the
// /admin ledger browser: filtering by shard-ID hex prefix and/or owner key is done
// in SQL so it scales past the rendered page, and Total lets the UI paginate.
func (l *Ledger) Entries(f LedgerFilter) (EntriesResult, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultEntryLimit
	}
	offset := max(f.Offset, 0)
	where, args := ledgerFilterClause(f)

	res := EntriesResult{Limit: limit, Offset: offset}
	// Total matching rows (for pagination), independent of the page window. The
	// WHERE only touches `shards s` and correlated subqueries, so it is valid here
	// without the stripe join.
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM shards s`+where, args...).Scan(&res.Total); err != nil {
		return EntriesResult{}, err
	}

	q := `SELECT s.id, s.size, s.created,
	             (SELECT COUNT(*) FROM owners o2 WHERE o2.shard_id = s.id),
	             st.k, st.m, COALESCE(length(st.siblings), 0)
	      FROM shards s
	      LEFT JOIN stripes st ON st.shard_id = s.id` + where +
		` ORDER BY s.created DESC, s.id LIMIT ? OFFSET ?`
	rows, err := l.db.Query(q, append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return EntriesResult{}, err
	}
	defer rows.Close()

	idLen := len(store.ShardID{})
	for rows.Next() {
		var (
			idRaw    []byte
			e        LedgerEntry
			k, m     sql.NullInt64
			sibBytes int64
		)
		if err := rows.Scan(&idRaw, &e.Size, &e.Created, &e.OwnerCount, &k, &m, &sibBytes); err != nil {
			return EntriesResult{}, err
		}
		if len(idRaw) != idLen {
			return EntriesResult{}, fmt.Errorf("ledger: entry shard_id is %d bytes, want %d", len(idRaw), idLen)
		}
		copy(e.ShardID[:], idRaw)
		// A shard with no stripe row LEFT-JOINs to NULL k/m; only then is it un-striped.
		e.HasStripe = k.Valid
		e.K, e.M = int(k.Int64), int(m.Int64)
		e.Siblings = int(sibBytes) / idLen
		res.Entries = append(res.Entries, e)
	}
	return res, rows.Err()
}

// ledgerFilterClause builds the SQL WHERE clause (with a leading " WHERE " when
// non-empty) and its bound arguments for a LedgerFilter. The shard prefix matches
// against SQLite's uppercase hex() of the id; the owner is an exact-key membership
// test via a correlated EXISTS.
func ledgerFilterClause(f LedgerFilter) (string, []any) {
	var conds []string
	var args []any
	if p := strings.TrimSpace(f.ShardHexPrefix); p != "" {
		conds = append(conds, `hex(s.id) LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(strings.ToUpper(p))+"%")
	}
	if len(f.Owner) > 0 {
		conds = append(conds, `EXISTS (SELECT 1 FROM owners o WHERE o.shard_id = s.id AND o.owner = ?)`)
		args = append(args, f.Owner)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// escapeLike escapes the SQL LIKE metacharacters (%, _, and the \ escape itself) in
// s so it matches literally under `LIKE ... ESCAPE '\'`.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// StripeRow is the erasure context a node records for one shard it holds: the
// stripe's K/M, its sibling shard IDs (in erasure-position order), and the signed
// repair grant that authorizes regenerating and re-placing the stripe's shards.
// The repair loop enumerates these to decide what to probe and repair.
type StripeRow struct {
	ShardID  store.ShardID
	K, M     int
	Siblings []store.ShardID
	Grant    []byte
}

// PutStripe records (or replaces) the stripe context for a shard this node holds.
// The shard must already have a row in `shards` (i.e. AddOwner ran first); the
// foreign key ties the stripe row's lifetime to the blob, so when the last owner
// leaves and the shard row is dropped, the stripe row cascades away too. siblings
// is stored in position order as a flat 32-byte-per-id blob.
func (l *Ledger) PutStripe(id store.ShardID, k, m int, siblings []store.ShardID, grant []byte) error {
	if len(grant) == 0 {
		return fmt.Errorf("ledger: PutStripe requires a non-empty grant")
	}
	blob := make([]byte, 0, len(siblings)*len(store.ShardID{}))
	for _, s := range siblings {
		blob = append(blob, s[:]...)
	}
	_, err := l.db.Exec(`INSERT OR REPLACE INTO stripes (shard_id, k, m, siblings, grant) VALUES (?, ?, ?, ?, ?)`,
		id[:], k, m, blob, grant)
	return err
}

// Stripes returns every stripe context this node currently holds. The repair
// loop deduplicates by sibling set (several rows can describe the same stripe
// when a node holds more than one of its shards).
func (l *Ledger) Stripes() ([]StripeRow, error) {
	rows, err := l.db.Query(`SELECT shard_id, k, m, siblings, grant FROM stripes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStripeRows(rows)
}

// ColdShards returns up to limit stripe contexts for the shards this node holds,
// oldest-stored first, so a rebalancer offloads its *coldest* shards — the
// least-recently written, least likely to be in active use — to an emptier peer
// (Architecture §3.4). Only shards with a recorded stripe row are returned: the
// repair grant on that row is exactly what authorizes moving the shard to another
// node without the User's signing key. A limit <= 0 returns all such shards.
func (l *Ledger) ColdShards(limit int) ([]StripeRow, error) {
	q := `SELECT st.shard_id, st.k, st.m, st.siblings, st.grant
	      FROM stripes st JOIN shards s ON s.id = st.shard_id
	      ORDER BY s.created ASC, st.shard_id ASC`
	var args []any
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := l.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStripeRows(rows)
}

// scanStripeRows decodes a result set of (shard_id, k, m, siblings, grant) rows
// into StripeRows, unpacking the flat 32-byte-per-id siblings blob back into
// position order. Shared by Stripes and ColdShards.
func scanStripeRows(rows *sql.Rows) ([]StripeRow, error) {
	idLen := len(store.ShardID{})
	var out []StripeRow
	for rows.Next() {
		var (
			idRaw    []byte
			sr       StripeRow
			siblings []byte
		)
		if err := rows.Scan(&idRaw, &sr.K, &sr.M, &siblings, &sr.Grant); err != nil {
			return nil, err
		}
		if len(idRaw) != idLen {
			return nil, fmt.Errorf("ledger: stripe shard_id is %d bytes, want %d", len(idRaw), idLen)
		}
		copy(sr.ShardID[:], idRaw)
		if len(siblings)%idLen != 0 {
			return nil, fmt.Errorf("ledger: stripe siblings blob is %d bytes, not a multiple of %d", len(siblings), idLen)
		}
		sr.Siblings = make([]store.ShardID, len(siblings)/idLen)
		for i := range sr.Siblings {
			copy(sr.Siblings[i][:], siblings[i*idLen:(i+1)*idLen])
		}
		out = append(out, sr)
	}
	return out, rows.Err()
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
	// Rebuild first_seen from the earliest surviving claim per owner (MIN put_at),
	// so the age-graduated quota (Axis B) is not reset to epoch by a reconcile.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO accounts (owner, bytes_used, shard_count, first_seen)
		SELECT o.owner, COALESCE(SUM(s.size), 0), COUNT(*), MIN(o.put_at)
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
