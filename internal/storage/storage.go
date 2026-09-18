// Package storage exposes the same transactional interface for SQLite and MySQL.
// Records carry typed JSON documents; secret documents contain ciphertext only.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("record not found")

// Tx isolates persistence from service logic. Update callbacks must not call the
// store recursively: all reads and writes belong to this transaction.
type Tx interface {
	Get(kind, id string, out any) error
	Put(kind, id string, value any) error
	Delete(kind, id string) error
	List(kind string) ([]json.RawMessage, error)
}
type Store interface {
	Update(context.Context, func(Tx) error) error
	Ping(context.Context) error
	Close() error
	SchemaVersion(context.Context) (int, error)
	Scan(context.Context, string, func(json.RawMessage) error) error
}
type SQLStore struct{ db *sql.DB }
type sqlTx struct{ tx *sql.Tx }

// Open applies migrations before accepting traffic. One connection keeps SQLite
// write ordering predictable; the DB mutex row also serializes MySQL processes.
func Open(ctx context.Context, driver, dsn string) (*SQLStore, error) {
	if driver != "sqlite" && driver != "mysql" {
		return nil, errors.New("storage driver must be sqlite or mysql")
	}
	db, e := sql.Open(driver, dsn)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &SQLStore{db}
	if e = db.PingContext(ctx); e != nil {
		db.Close()
		return nil, e
	}
	if driver == "sqlite" {
		if _, e = db.ExecContext(ctx, "PRAGMA busy_timeout=10000"); e != nil {
			db.Close()
			return nil, e
		}
		if _, e = db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); e != nil {
			db.Close()
			return nil, e
		}
	}
	if e = s.migrate(ctx, driver); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}

// Migration 1 is deliberately idempotent, including on MySQL where DDL commits
// implicitly. The version is advanced only after every required table exists.
func (s *SQLStore) migrate(ctx context.Context, driver string) error {
	suffix := ""
	if driver == "mysql" {
		suffix = " ENGINE=InnoDB"
	}
	statements := []string{
		"CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)" + suffix,
		"CREATE TABLE IF NOT EXISTS ssm_mutex (id INTEGER PRIMARY KEY, counter BIGINT NOT NULL)" + suffix,
		"CREATE TABLE IF NOT EXISTS records (kind VARCHAR(32) NOT NULL, id VARCHAR(512) NOT NULL, document LONGBLOB NOT NULL, PRIMARY KEY(kind,id))" + suffix,
	}
	// Binary collation makes MySQL identifiers case-sensitive just like SQLite.
	if driver == "mysql" {
		statements[2] = "CREATE TABLE IF NOT EXISTS records (kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, id VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL, document LONGBLOB NOT NULL, PRIMARY KEY(kind,id)) ENGINE=InnoDB"
	}
	for _, q := range statements {
		if _, e := s.db.ExecContext(ctx, q); e != nil {
			return fmt.Errorf("migration: %w", e)
		}
	}
	insert := "INSERT OR IGNORE"
	if driver == "mysql" {
		insert = "INSERT IGNORE"
	}
	if _, e := s.db.ExecContext(ctx, insert+" INTO ssm_mutex (id,counter) VALUES (1,0)"); e != nil {
		return e
	}
	v, e := s.SchemaVersion(ctx)
	if e != nil {
		return e
	}
	if v > 1 {
		return errors.New("database schema is newer than this binary")
	}
	_, e = s.db.ExecContext(ctx, insert+" INTO schema_migrations (version) VALUES (1)")
	return e
}
func (s *SQLStore) SchemaVersion(ctx context.Context) (int, error) {
	var n int
	e := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&n)
	return n, e
}
func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *SQLStore) Close() error                   { return s.db.Close() }
func (s *SQLStore) Update(ctx context.Context, fn func(Tx) error) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// Taking this row's write lock makes token redemption and revision updates
	// atomic even if multiple clients race for the same record.
	if _, e = tx.ExecContext(ctx, "UPDATE ssm_mutex SET counter=counter WHERE id=1"); e != nil {
		return e
	}
	if e = fn(&sqlTx{tx}); e != nil {
		return e
	}
	return tx.Commit()
}
func (t *sqlTx) Get(kind, id string, out any) error {
	var b []byte
	e := t.tx.QueryRow("SELECT document FROM records WHERE kind=? AND id=?", kind, id).Scan(&b)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, out)
}
func (t *sqlTx) Put(kind, id string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var exists int
	e = t.tx.QueryRow("SELECT 1 FROM records WHERE kind=? AND id=?", kind, id).Scan(&exists)
	if errors.Is(e, sql.ErrNoRows) {
		_, e = t.tx.Exec("INSERT INTO records(kind,id,document) VALUES(?,?,?)", kind, id, b)
	} else if e == nil {
		_, e = t.tx.Exec("UPDATE records SET document=? WHERE kind=? AND id=?", b, kind, id)
	}
	return e
}
func (t *sqlTx) Delete(kind, id string) error {
	_, e := t.tx.Exec("DELETE FROM records WHERE kind=? AND id=?", kind, id)
	return e
}
func (t *sqlTx) List(kind string) ([]json.RawMessage, error) {
	rows, e := t.tx.Query("SELECT document FROM records WHERE kind=? ORDER BY id", kind)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		out = append(out, json.RawMessage(b))
	}
	return out, rows.Err()
}

// Scan exports records in bounded batches. It releases the database connection
// before calling the consumer, so a slow download cannot monopolize the single
// connection used by this store. A fixed upper ID keeps new audit activity from
// extending a download forever. Audit records are append-only.
func (s *SQLStore) Scan(ctx context.Context, kind string, visit func(json.RawMessage) error) error {
	var upper string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),'') FROM records WHERE kind=?", kind).Scan(&upper); err != nil {
		return err
	}
	after := ""
	for after < upper {
		rows, err := s.db.QueryContext(ctx, "SELECT id,document FROM records WHERE kind=? AND id>? AND id<=? ORDER BY id LIMIT 256", kind, after, upper)
		if err != nil {
			return err
		}
		batch := make([]json.RawMessage, 0, 256)
		for rows.Next() {
			var id string
			var document []byte
			if err = rows.Scan(&id, &document); err != nil {
				rows.Close()
				return err
			}
			after = id
			batch = append(batch, json.RawMessage(document))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, document := range batch {
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = visit(document); err != nil {
				return err
			}
		}
	}
	return nil
}
