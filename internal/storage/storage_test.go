package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The identical contract runs on both real engines. MYSQL_TEST_DSN must point
// to a disposable database: these tests own and remove their records.
func contract(t *testing.T, driver, dsn string) {
	t.Helper()
	ctx := context.Background()
	s, e := Open(ctx, driver, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v, e := s.SchemaVersion(ctx)
	if e != nil || v != 1 {
		t.Fatalf("migration version %d: %v", v, e)
	}
	if e = s.migrate(ctx, driver); e != nil {
		t.Fatalf("idempotent migration: %v", e)
	}
	type record struct {
		Revision int
		Value    string
	}
	kind := "test"
	id := t.Name()
	defer s.Update(ctx, func(tx Tx) error { return tx.Delete(kind, id) })
	if e = s.Update(ctx, func(tx Tx) error { return tx.Put(kind, id, record{1, "ciphertext"}) }); e != nil {
		t.Fatal(e)
	}
	rollback := errors.New("rollback")
	if e = s.Update(ctx, func(tx Tx) error {
		if e := tx.Put(kind, id, record{99, "not committed"}); e != nil {
			return e
		}
		return rollback
	}); !errors.Is(e, rollback) {
		t.Fatal(e)
	}
	if e = s.Update(ctx, func(tx Tx) error {
		var r record
		if e := tx.Get(kind, id, &r); e != nil {
			return e
		}
		if r.Revision != 1 {
			t.Fatal("rollback failed")
		}
		rows, e := tx.List(kind)
		if len(rows) == 0 {
			t.Fatal("empty list")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// Use two independent connections, as separate server processes would.
	peer, e := Open(ctx, driver, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		target := s
		if i%2 == 0 {
			target = peer
		}
		go func() {
			defer wg.Done()
			if e := target.Update(ctx, func(tx Tx) error {
				var r record
				if e := tx.Get(kind, id, &r); e != nil {
					return e
				}
				r.Revision++
				return tx.Put(kind, id, r)
			}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if e = s.Update(ctx, func(tx Tx) error {
		var r record
		if e := tx.Get(kind, id, &r); e != nil {
			return e
		}
		if r.Revision != 11 {
			t.Errorf("lost update: %d", r.Revision)
		}
		if e := tx.Delete(kind, id); e != nil {
			return e
		}
		if e := tx.Get(kind, id, &r); !errors.Is(e, ErrNotFound) {
			t.Errorf("missing: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestSQLiteStorageAndMigrations(t *testing.T) {
	contract(t, "sqlite", filepath.Join(t.TempDir(), "test.db"))
}
func TestMySQLStorageAndMigrations(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set MYSQL_TEST_DSN to a disposable MySQL database")
	}
	contract(t, "mysql", dsn)
}
func TestSQLitePersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persist.db")
	s, e := Open(ctx, "sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update(ctx, func(tx Tx) error { return tx.Put("test", "record", map[string]int{"revision": 7}) }); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(ctx, "sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Update(ctx, func(tx Tx) error {
		var r map[string]int
		if e := tx.Get("test", "record", &r); e != nil {
			return e
		}
		if r["revision"] != 7 {
			t.Fatal("record not persisted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestFutureSchemaRejected(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "future.db")
	s, e := Open(ctx, "sqlite", dsn)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("INSERT INTO schema_migrations(version) VALUES (999)"); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if newer, e := Open(ctx, "sqlite", dsn); e == nil {
		newer.Close()
		t.Fatal("future schema accepted")
	}
}

// Scan must stop at its initial high-water mark and release the connection
// before invoking callbacks, including when a callback writes another record.
func scanContract(t *testing.T, driver, dsn string) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	kind := "test"
	defer s.db.Exec("DELETE FROM records WHERE kind=?", kind)
	if err = s.Update(ctx, func(tx Tx) error {
		for i := 0; i < 600; i++ {
			if err := tx.Put(kind, fmt.Sprintf("%06d", i), map[string]int{"n": i}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	count := 0
	if err = s.Scan(bounded, kind, func(raw json.RawMessage) error {
		var item map[string]int
		if e := json.Unmarshal(raw, &item); e != nil {
			return e
		}
		if item["n"] != count {
			t.Errorf("out of order: %d", item["n"])
		}
		count++
		if count == 1 {
			return s.Update(bounded, func(tx Tx) error { return tx.Put(kind, "999999", map[string]int{"n": 999999}) })
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 600 {
		t.Fatalf("export followed new records or lost data: %d", count)
	}
	stop := errors.New("consumer stopped")
	if err = s.Scan(ctx, kind, func(json.RawMessage) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("consumer error ignored")
	}
	canceled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if err = s.Scan(canceled, kind, func(json.RawMessage) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
func TestSQLiteScan(t *testing.T) { scanContract(t, "sqlite", filepath.Join(t.TempDir(), "scan.db")) }
func TestMySQLScan(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("MYSQL_TEST_DSN not set")
	}
	scanContract(t, "mysql", dsn)
}
