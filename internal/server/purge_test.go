package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	// Oversized and malformed events must never enter the parser or abort a job.
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		if err := tx.Put("audit", "oversized", map[string]any{"timestamp": cutoff.Add(-time.Hour), "padding": strings.Repeat("x", 2*1024*1024)}); err != nil {
			return err
		}
		return tx.Put("audit", "malformed", map[string]string{"timestamp": "invalid"})
	}))
	var upper, cursor string
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error { var err error; upper, err = tx.AuditUpperID(); return err }))
	var deleted, skipped int64
	batches := 0
	for {
		var batch storage.PurgeBatch
		must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
			var err error
			batch, err = tx.PurgeAuditBatch(cutoff, cursor, upper)
			return err
		}))
		if batch.Scanned > storage.PurgeBatchSize {
			t.Fatal("unbounded batch")
		}
		deleted += batch.Deleted
		skipped += batch.Skipped
		batches++
		cursor = batch.LastID
		if batch.Done {
			break
		}
	}
	if deleted != 601 || skipped != 3 || batches < 5 {
		t.Fatalf("deleted=%d skipped=%d batches=%d", deleted, skipped, batches)
	}

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
		return nil
	}))
	// Stop the worker to prove queueing and status do not require processing any
	// audit rows. A fresh server below resumes this durable job.
	f.app.Close()
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
	f.request("admin/audit/purge", "GET", nil, "", 200)
	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		if err := tx.Put("audit", "api-old", Audit{Time: time.Now().Add(-31 * 24 * time.Hour)}); err != nil {
			return err
		}
		return tx.Put("audit", "api-recent", Audit{Time: time.Now().Add(-time.Hour)})
	}))
	// Locked operation is intentional: audit data needs no secret decryption key.

	queued := f.request("admin/audit/purge", "POST", map[string]any{"days": 30, "confirm": true}, "", 202)
	if queued["state"] != "queued" || queued["scanned"] != float64(0) {
		t.Fatal("POST performed synchronous scan")
	}
	f.request("admin/audit/purge", "POST", map[string]any{"days": 30, "confirm": true}, "", 409)
	status := f.request("admin/audit/purge", "GET", nil, "", 200)
	if status["id"] != queued["id"] || status["state"] != "queued" {
		t.Fatal("job not durable")
	}
	resumed := New(f.app.Store, time.Hour, f.app.Log)
	defer resumed.Close()
	waitPurge(t, f)

	must(f.app.Store.Update(ctx, func(tx storage.Tx) error {
		var a Audit
		if err := tx.Get("audit", "api-old", &a); !errors.Is(err, storage.ErrNotFound) {
			t.Fatal("expired record survived")
		}
		return tx.Get("audit", "api-recent", &a)
	}))
	f.request("admin/audit/purge", "POST", map[string]any{"days": 0, "confirm": true}, "", 202)
	result := waitPurge(t, f)
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
				continue
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

// Poll only the small job document, just as the browser does.
func waitPurge(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		result := f.request("admin/audit/purge", "GET", nil, "", 200)
		if result["state"] == "completed" {
			return result
		}
		if result["state"] == "failed" {
			t.Fatalf("purge failed: %v", result)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("purge did not complete")
	return nil
}

// Interrupt the second transaction after it has deleted rows but before commit.
// This models shutdown/database failure and checks both data and durable counters.
type interruptedPurgeStore struct {
	storage.Store
	entered  chan struct{}
	batches  int
	shutdown bool
}
type interruptedPurgeTx struct {
	storage.Tx
	owner *interruptedPurgeStore
	ctx   context.Context
}

func (s *interruptedPurgeStore) Update(ctx context.Context, fn func(storage.Tx) error) error {
	return s.Store.Update(ctx, func(tx storage.Tx) error { return fn(&interruptedPurgeTx{Tx: tx, owner: s, ctx: ctx}) })
}
func (t *interruptedPurgeTx) PurgeAuditBatch(cutoff time.Time, after, upper string) (storage.PurgeBatch, error) {
	batch, err := t.Tx.PurgeAuditBatch(cutoff, after, upper)
	if err != nil {
		return batch, err
	}
	t.owner.batches++
	if t.owner.batches == 2 {
		close(t.owner.entered)
		if t.owner.shutdown {
			<-t.ctx.Done()
			return batch, t.ctx.Err()
		}
		return batch, errors.New("injected batch failure")
	}
	return batch, nil
}
func TestPurgePartialProgress(t *testing.T) {
	for _, shutdown := range []bool{true, false} {
		t.Run(fmt.Sprintf("shutdown=%v", shutdown), func(t *testing.T) {
			f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "progress.db"))
			f.app.Close()
			ctx := context.Background()
			err := f.app.Store.Update(ctx, func(tx storage.Tx) error {
				for i := 0; i < 700; i++ {
					if err := tx.Put("audit", fmt.Sprintf("event-%04d", i), Audit{Time: time.Now().Add(-48 * time.Hour)}); err != nil {
						return err
					}
				}
				return tx.Put("maintenance", "audit-purge", PurgeJob{ID: "test", State: "queued", Cutoff: time.Now(), Upper: "event-0699", Actor: "admin:test"})
			})
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &interruptedPurgeStore{Store: f.app.Store, entered: make(chan struct{}), shutdown: shutdown}
			worker := New(wrapped, time.Hour, f.app.Log)
			defer worker.Close()
			select {
			case <-wrapped.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not reach second batch")
			}
			if shutdown {
				worker.Close()
			} else {
				deadline := time.Now().Add(5 * time.Second)
				for {
					var job PurgeJob
					if err := f.app.Store.Update(ctx, func(tx storage.Tx) error { var err error; job, err = readPurgeJob(tx); return err }); err != nil {
						t.Fatal(err)
					}
					if job.State == "failed" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("failure not persisted")
					}
					time.Sleep(10 * time.Millisecond)
				}
				worker.Close()
			}
			err = f.app.Store.Update(ctx, func(tx storage.Tx) error {
				job, err := readPurgeJob(tx)
				if err != nil {
					return err
				}
				if job.Deleted != 128 || job.Scanned != 128 || job.Cursor != "event-0127" {
					t.Fatalf("uncommitted progress persisted: %+v", job)
				}
				var a Audit
				if err := tx.Get("audit", "event-0000", &a); !errors.Is(err, storage.ErrNotFound) {
					t.Fatal("first batch not committed")
				}
				if err := tx.Get("audit", "event-0128", &a); err != nil {
					return err
				}
				if !shutdown {
					job.State = "queued"
					return tx.Put("maintenance", "audit-purge", job)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			resumed := New(f.app.Store, time.Hour, f.app.Log)
			defer resumed.Close()
			f.login()
			result := waitPurge(t, f)
			if result["deleted"] != float64(700) || result["scanned"] != float64(700) {
				t.Fatalf("resume lost/doubled progress: %v", result)
			}
		})
	}
}
