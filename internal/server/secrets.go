package server

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

// secret is called only after the route has authenticated and authorized the
// caller. Metadata responses contain no value or ciphertext. Value responses use
// data.value consistently, including for the ESO generic webhook provider.
func (s *Server) secret(t storage.Tx, r *http.Request, path string, metadata bool) (any, error) {
	p, e := security.Normalize(path)
	if e != nil {
		return nil, bad(e.Error())
	}
	if s.Vault.Locked() {
		return nil, security.ErrLocked
	}
	var record Secret
	e = t.Get("secrets", p, &record)
	exists := e == nil && !record.Deleted
	if e != nil && !errors.Is(e, storage.ErrNotFound) {
		return nil, e
	}
	switch r.Method {
	case "GET":
		if !exists {
			return nil, storage.ErrNotFound
		}
		if metadata {
			record.Ciphertext = nil
			return record, nil
		}
		value, e := s.Vault.Decrypt(p, record.Ciphertext)
		if e != nil {
			return nil, e
		}
		return map[string]any{"data": map[string]string{"value": string(value)}, "path": p, "revision": record.Revision, "created_at": record.Created, "updated_at": record.Updated}, nil
	case "POST", "PUT":
		if r.Method == "POST" && exists {
			return nil, &apiError{409, "secret already exists"}
		}
		if r.Method == "PUT" && !exists {
			return nil, storage.ErrNotFound
		}
		var in struct {
			Value *string `json:"value"`
		}
		if e = decode(r, &in); e != nil {
			return nil, e
		}
		if in.Value == nil {
			return nil, bad("value is required")
		}
		changed := true
		if exists {
			old, e := s.Vault.Decrypt(p, record.Ciphertext)
			if e != nil {
				return nil, e
			}
			changed = !bytes.Equal(old, []byte(*in.Value))
		}
		if changed {
			encrypted, e := s.Vault.Encrypt(p, []byte(*in.Value))
			if e != nil {
				return nil, e
			}
			now := time.Now().UTC()
			if record.Created.IsZero() {
				record.Created = now
			}
			record.Path = p
			record.Revision++
			record.Updated = now
			record.Ciphertext = encrypted
			record.Algorithm = "AES-256-GCM"
			record.Deleted = false
			if e = t.Put("secrets", p, record); e != nil {
				return nil, e
			}
		}
		record.Ciphertext = nil
		return record, nil
	case "DELETE":
		if !exists {
			return nil, storage.ErrNotFound
		}
		record.Deleted = true
		record.Ciphertext = nil
		record.Updated = time.Now().UTC()
		if e = t.Put("secrets", p, record); e != nil {
			return nil, e
		}
		return map[string]bool{"ok": true}, nil
	default:
		return nil, &apiError{405, "method not allowed"}
	}
}
