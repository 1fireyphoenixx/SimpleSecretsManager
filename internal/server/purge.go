package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

// Only the latest job is retained. Its cursor and counters commit in the SAME
// transaction as each batch of deletions, so a restart cannot lose progress or
// count an uncommitted deletion. No audit documents are stored in job status.
type PurgeJob struct {
	ID      string    `json:"id,omitempty"`
	State   string    `json:"state"`
	Days    int       `json:"days_kept"`
	Cutoff  time.Time `json:"cutoff"`
	Started time.Time `json:"started_at"`
	Updated time.Time `json:"updated_at"`
	Scanned int64     `json:"scanned"`
	Deleted int64     `json:"deleted"`
	Skipped int64     `json:"skipped"`
	Error   string    `json:"error,omitempty"`
	Actor   string    `json:"actor,omitempty"`
	Source  string    `json:"source,omitempty"`
	// These bounded internal cursor fields are safe identifiers, not credentials.
	Cursor string `json:"cursor,omitempty"`
	Upper  string `json:"upper_id,omitempty"`
}

func readPurgeJob(t storage.Tx) (PurgeJob, error) {
	var job PurgeJob
	err := t.Get("maintenance", "audit-purge", &job)
	if errors.Is(err, storage.ErrNotFound) {
		return PurgeJob{State: "idle"}, nil
	}
	return job, err
}
func activePurge(job PurgeJob) bool { return job.State == "queued" || job.State == "running" }
func queueAuditPurge(t storage.Tx, r *http.Request, actor string) (PurgeJob, error) {
	var in struct {
		Days    *int `json:"days"`
		Confirm bool `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		return PurgeJob{}, err
	}
	if in.Days == nil || *in.Days < 0 || *in.Days > 36500 {
		return PurgeJob{}, bad("days must be a whole number from 0 to 36500")
	}
	if !in.Confirm {
		return PurgeJob{}, bad("explicit purge confirmation is required")
	}
	previous, err := readPurgeJob(t)
	if err != nil {
		return PurgeJob{}, err
	}
	if activePurge(previous) {
		return PurgeJob{}, &apiError{409, "an audit purge is already queued or running"}
	}
	upper, err := t.AuditUpperID()
	if err != nil {
		return PurgeJob{}, err
	}
	now := time.Now().UTC()
	job := PurgeJob{ID: security.Token(), State: "queued", Days: *in.Days, Cutoff: now.Add(-time.Duration(*in.Days) * 24 * time.Hour), Started: now, Updated: now, Upper: upper, Actor: actor, Source: r.RemoteAddr}
	return job, t.Put("maintenance", "audit-purge", job)
}

// Close stops maintenance before the caller closes the database. Cancellation
// rolls back only the in-flight batch; the durable running job resumes on startup.
func (s *Server) Close() { s.purgeCancel(); <-s.purgeDone }
func (s *Server) runPurgeWorker(ctx context.Context) {
	defer close(s.purgeDone)
	delay := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		// Bound a single DB transaction. A slow or failing batch must not retain the
		// global database mutex indefinitely or share an HTTP request's lifetime.
		batchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var job PurgeJob
		active := false
		err := s.Store.Update(batchCtx, func(t storage.Tx) error {
			var err error
			job, err = readPurgeJob(t)
			if err != nil {
				return err
			}
			if !activePurge(job) {
				return nil
			}
			active = true
			batch, err := t.PurgeAuditBatch(job.Cutoff, job.Cursor, job.Upper)
			if err != nil {
				return err
			}
			job.Cursor = batch.LastID
			job.Scanned += batch.Scanned
			job.Deleted += batch.Deleted
			job.Skipped += batch.Skipped
			job.Updated = time.Now().UTC()
			job.State = "running"
			if batch.Done {
				job.State = "completed"
				if err = purgeCompletionAudit(t, job, true); err != nil {
					return err
				}
			}
			return t.Put("maintenance", "audit-purge", job)
		})
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.Log.Error("audit purge batch failed")
			if active {
				s.failPurge(ctx, job.ID)
			}
			delay = time.Second
		} else if active && job.State == "running" {
			delay = 10 * time.Millisecond
		} else {
			delay = time.Second
		}
	}
}
func purgeCompletionAudit(t storage.Tx, job PurgeJob, success bool) error {
	now := time.Now().UTC()
	operation := "audit purge completed"
	if !success {
		operation = "audit purge failed"
	}
	return t.Put("audit", now.Format(time.RFC3339Nano)+"-"+security.Token(), Audit{Time: now, Identity: job.Actor, Operation: operation, Success: success, Source: job.Source})
}
func (s *Server) failPurge(ctx context.Context, id string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Reload after rollback: the local job value may include uncommitted counters.
	err := s.Store.Update(ctx, func(t storage.Tx) error {
		job, err := readPurgeJob(t)
		if err != nil {
			return err
		}
		if job.ID != id || !activePurge(job) {
			return nil
		}
		job.State = "failed"
		job.Updated = time.Now().UTC()
		job.Error = "Database batch failed. Earlier committed batches remain applied; you may retry the purge."
		if err = t.Put("maintenance", "audit-purge", job); err != nil {
			return err
		}
		return purgeCompletionAudit(t, job, false)
	})
	if err != nil {
		s.Log.Error("could not persist audit purge failure; job remains resumable")
	}
}
