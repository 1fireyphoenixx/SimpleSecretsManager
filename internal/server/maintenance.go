package server

import (
	"encoding/json"
	"net/http"
	"time"

	"simplesecretsmanager/internal/storage"
)

// deleteAgent removes one identity and all of its enrollment tokens (unused,
// expired, and consumed), plus its runtime credential index. The caller holds
// the store transaction, so enrollment cannot race deletion. Audit history and
// secrets belong to the server and are deliberately retained.
func deleteAgent(t storage.Tx, id string) error {
	var agent Agent
	if err := t.Get("agents", id, &agent); err != nil {
		return err
	}
	rows, err := t.List("enrollment")
	if err != nil {
		return err
	}
	for _, row := range rows {
		var token Enrollment
		if err = json.Unmarshal(row, &token); err != nil {
			return err
		}
		if token.AgentID == id {
			if err = t.Delete("enrollment", token.Hash); err != nil {
				return err
			}
		}
	}
	if agent.Hash != "" {
		if err = t.Delete("credentials", agent.Hash); err != nil {
			return err
		}
	}
	return t.Delete("agents", id)
}

type auditDownload struct{}

// downloadAudit is reached only after administrator authentication and auditing
// in ServeHTTP. An attachment response lets the browser's download manager write
// directly to disk: there is no fetch().json(), DOM table, or Blob of the log.
func (s *Server) downloadAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="ssm-audit-`+time.Now().UTC().Format("20060102T150405Z")+`.txt"`)
	w.Header().Set("X-Accel-Buffering", "no")
	control := http.NewResponseController(w)
	encoder := json.NewEncoder(w)
	started := false
	err := s.Store.Scan(r.Context(), "audit", func(raw json.RawMessage) error {
		// Each line is one structured event. Refresh the write deadline for progress,
		// allowing large exports without the normal API's fixed response timeout.
		if err := control.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil && err != http.ErrNotSupported {
			return err
		}
		started = true
		if err := encoder.Encode(raw); err != nil {
			return err
		}
		err := control.Flush()
		if err == http.ErrNotSupported {
			return nil
		}
		return err
	})
	if err != nil {
		s.Log.Error("audit download interrupted")
		if !started {
			w.Header().Del("Content-Disposition")
			write(w, 503, map[string]string{"error": "audit download unavailable"})
			return
		}
		// Do not turn a truncated export into an apparently successful file. Aborting
		// the response lets HTTP clients report an incomplete/failed download.
		panic(http.ErrAbortHandler)
	}
}
