package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

// WriteCredential is independent of an agent identity. It grants updates only:
// possessing it never permits reading values, creating secrets, or using the UI.
// Hash is persisted but removed from every administrative response. The random
// plaintext token is returned exactly once, in the creation response.
type WriteCredential struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Paths   []string  `json:"paths"`
	Hash    string    `json:"credential_hash,omitempty"`
	Revoked bool      `json:"revoked"`
	Created time.Time `json:"created_at"`
}

// manageWriteCredentials runs behind administrator session and CSRF checks.
// The existing transactional record store supports these new record kinds on
// both engines, so this additive feature does not need a SQL schema migration.
func manageWriteCredentials(t storage.Tx, r *http.Request) (any, error) {
	const base = "/api/v1/admin/write-credentials"
	if r.URL.Path == base {
		switch r.Method {
		case "GET":
			rows, e := t.List("writers")
			if e != nil {
				return nil, e
			}
			out := []WriteCredential{}
			for _, b := range rows {
				var c WriteCredential
				if e = json.Unmarshal(b, &c); e != nil {
					return nil, e
				}
				c.Hash = ""
				out = append(out, c)
			}
			return out, nil
		case "POST":
			var in struct {
				Name  string   `json:"name"`
				Paths []string `json:"paths"`
			}
			if e := decode(r, &in); e != nil {
				return nil, e
			}
			if strings.TrimSpace(in.Name) == "" {
				return nil, bad("name required")
			}
			if e := security.ValidateRules(in.Paths); e != nil {
				return nil, bad(e.Error())
			}
			token := security.Token()
			c := WriteCredential{ID: security.Token(), Name: in.Name, Paths: in.Paths, Hash: security.Hash(token), Created: time.Now().UTC()}
			if e := t.Put("writers", c.ID, c); e != nil {
				return nil, e
			}
			if e := t.Put("writer_tokens", c.Hash, map[string]string{"ID": c.ID}); e != nil {
				return nil, e
			}
			c.Hash = ""
			return map[string]any{"credential": c, "token": token}, nil
		default:
			return nil, &apiError{405, "method not allowed"}
		}
	}
	id := strings.TrimPrefix(r.URL.Path, base+"/")
	var c WriteCredential
	if e := t.Get("writers", id, &c); e != nil {
		return nil, e
	}
	switch r.Method {
	case "PUT":
		var in struct {
			Paths []string `json:"paths"`
		}
		if e := decode(r, &in); e != nil {
			return nil, e
		}
		if e := security.ValidateRules(in.Paths); e != nil {
			return nil, bad(e.Error())
		}
		c.Paths = in.Paths
	case "DELETE":
		// Revocation is permanent. Keeping the identity makes historical audit
		// entries understandable; removing its token index stops authentication.
		c.Revoked = true
		if e := t.Delete("writer_tokens", c.Hash); e != nil {
			return nil, e
		}
	default:
		return nil, &apiError{405, "method not allowed"}
	}
	if e := t.Put("writers", c.ID, c); e != nil {
		return nil, e
	}
	c.Hash = ""
	return c, nil
}

// writeSecret accepts a simple POST but deliberately uses the existing update
// behavior. Missing or deleted secrets return 404 instead of being created.
// Cloning preserves the original POST method in audit and structured logs.
func (s *Server) writeSecret(t storage.Tx, r *http.Request, identity, path *string) (any, error) {
	c, e := authenticateWriter(t, r)
	if e != nil {
		return nil, e
	}
	*identity = "writer:" + c.ID
	*path = strings.TrimPrefix(r.URL.Path, "/api/v1/write/")
	normalized, e := security.Normalize(*path)
	if e != nil {
		return nil, bad(e.Error())
	}
	*path = normalized
	if !security.Allowed(normalized, c.Paths) {
		return nil, errForbidden
	}
	if r.Method != "POST" {
		return nil, &apiError{405, "method not allowed"}
	}
	update := r.Clone(r.Context())
	update.Method = "PUT"
	return s.secret(t, update, normalized, false)
}
