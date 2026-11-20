package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"simplesecretsmanager/internal/storage"
)

func TestAuditRetention(t *testing.T) {
	auditRetention(t, "sqlite", filepath.Join(t.TempDir(), "retention.db"))
}
func TestMySQLAuditRetention(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("MYSQL_TEST_DSN not set")
	}
	bootstrap, err := storage.Open(context.Background(), "mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap.Close()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The disposable test database may contain a previous server fixture. Leave
	// storage package test records alone because packages run concurrently.
	if _, err = db.Exec("DELETE FROM records WHERE kind <> 'test'"); err != nil {
		t.Fatal(err)
	}
	auditRetention(t, "mysql", dsn)
}
func auditRetention(t *testing.T, driver, dsn string) {
	f := newFixture(t, driver, dsn)
	ctx := context.Background()
	cutoff := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Exercise more than two batches. Deliberately unrelated IDs prove that age
	// comes from the timestamp, not a lexicographic comparison of record keys.
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		for i := 0; i < 600; i++ {
			if err := tx.Put("audit", fmt.Sprintf("old-%04d", i), Audit{Time: cutoff.Add(-time.Nanosecond)}); err != nil {
				return err
			}
		}
		for id, event := range map[string]Audit{"equal": {Time: cutoff}, "newer": {Time: cutoff.Add(time.Second)}, "unknown": {}, "offset": {Time: cutoff.Add(-time.Second).In(time.FixedZone("test", -5*3600))}} {
			if err := tx.Put("audit", id, event); err != nil {
				return err
			}
		}
		for _, kind := range []string{"secrets", "agents", "credentials", "enrollment", "writers", "writer_tokens"} {
			if err := tx.Put(kind, "sentinel", map[string]string{"value": "preserve"}); err != nil {
				return err
			}
		}
		return nil
	}))
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		n, err := tx.PurgeAuditBefore(cutoff)
		if n != 601 {
			t.Errorf("deleted %d, want 601", n)
		}
		return err
	}))
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		for _, id := range []string{"equal", "newer", "unknown"} {
			var a Audit
			if err := tx.Get("audit", id, &a); err != nil {
				return err
			}
		}
		for _, kind := range []string{"secrets", "agents", "credentials", "enrollment", "writers", "writer_tokens"} {
			var data map[string]string
			if err := tx.Get(kind, "sentinel", &data); err != nil {
				return err
			}
			if data["value"] != "preserve" {
				t.Fatal("non-audit data changed")
			}
		}
		// An invalid event in a later batch must roll back earlier deletions.
		for i := 0; i < 300; i++ {
			if err := tx.Put("audit", fmt.Sprintf("rollback-%04d", i), Audit{Time: cutoff.Add(-time.Hour)}); err != nil {
				return err
			}
		}
		return tx.Put("audit", "z-malformed", map[string]string{"timestamp": "not a date"})
	}))
	if err := f.app.Store.Update(ctx, func(tx storage.Tx) error { _, err := tx.PurgeAuditBefore(cutoff); return err }); err == nil {
		t.Fatal("malformed timestamp accepted")
	}
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		var a Audit
		if err := tx.Get("audit", "rollback-0000", &a); err != nil {
			return err
		}
		return tx.Delete("audit", "z-malformed")
	}))
	// The API is authenticated, CSRF-protected, and requires explicit confirmation.
	f.request("admin/audit/purge", "POST", map[string]any{"days": 30, "confirm": true}, "", 401)
	f.login()
	csrf := f.csrf
	f.csrf = ""
	f.request("admin/audit/purge", "POST", map[string]any{"days": 30, "confirm": true}, "", 403)
	f.csrf = csrf
	for _, body := range []map[string]any{{"days": 30}, {"days": 30, "confirm": false}, {"confirm": true}, {"days": -1, "confirm": true}, {"days": 36501, "confirm": true}, {"days": 1.5, "confirm": true}, {"days": "30", "confirm": true}} {
		f.request("admin/audit/purge", "POST", body, "", 400)
	}
	f.request("admin/audit/purge", "GET", nil, "", 405)
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		if err := tx.Put("audit", "api-old", Audit{Time: time.Now().Add(-31 * 24 * time.Hour)}); err != nil {
			return err
		}
		return tx.Put("audit", "api-recent", Audit{Time: time.Now().Add(-time.Hour)})
	}))
	// Locked operation is intentional: audit data needs no secret decryption key.
	f.request("admin/audit/purge", "POST", map[string]any{"days": 30, "confirm": true}, "", 200)
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		var a Audit
		if err := tx.Get("audit", "api-old", &a); !errors.Is(err, storage.ErrNotFound) {
			t.Fatal("expired record survived")
		}
		return tx.Get("audit", "api-recent", &a)
	}))
	result := f.request("admin/audit/purge", "POST", map[string]any{"days": 0, "confirm": true}, "", 200)
	if result["days_kept"] != float64(0) || result["deleted"].(float64) == 0 {
		t.Fatal("invalid purge result")
	}
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		rows, err := tx.List("audit")
		if err != nil {
			return err
		}
		found := false
		for _, row := range rows {
			var a Audit
			if err = json.Unmarshal(row, &a); err != nil {
				return err
			}
			if a.Operation == "POST /api/v1/admin/audit/purge" && a.Identity == "admin:admin" && a.Success {
				found = true
			}
		}
		if !found {
			t.Fatal("purge erased its own audit trail")
		}
		return nil
	}))
	// Authentication and the wrapped key survive even an all-history purge.
	f.unlock()
}
