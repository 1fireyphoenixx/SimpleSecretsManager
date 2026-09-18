// Package server implements the versioned HTTPS API and its embedded WebUI.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
	"simplesecretsmanager/internal/version"
)

type Server struct {
	Store      storage.Store
	Vault      security.Vault
	SessionTTL time.Duration
	Log        *slog.Logger
	mu         sync.Mutex
	attempts   int
	window     time.Time
}

func New(st storage.Store, ttl time.Duration, log *slog.Logger) *Server {
	return &Server{Store: st, SessionTTL: ttl, Log: log}
}

// Setup is an offline operation, never a publicly accessible initialization API.
// The first administrator and envelope are committed together, and setup cannot
// overwrite an existing installation. Setup leaves the running vault locked.
func Setup(ctx context.Context, st storage.Store, name, password, master string) error {
	if strings.TrimSpace(name) == "" || len(password) < 12 {
		return errors.New("administrator name and password of at least 12 characters required")
	}
	p, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	en, e := security.NewEnvelope(master)
	if e != nil {
		return e
	}
	return st.Update(ctx, func(t storage.Tx) error {
		var old security.Envelope
		e := t.Get("config", "envelope", &old)
		if e == nil {
			return errors.New("already initialized")
		}
		if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		if e = t.Put("config", "envelope", en); e != nil {
			return e
		}
		return t.Put("admins", name, Admin{name, p})
	})
}
func decode(r *http.Request, out any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return bad("invalid JSON request")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return bad("invalid JSON request")
	}
	return nil
}

type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return e.msg }
func bad(s string) error          { return &apiError{400, s} }
func status(err error) int {
	var a *apiError
	switch {
	case errors.As(err, &a):
		return a.code
	case errors.Is(err, errUnauth):
		return 401
	case errors.Is(err, errForbidden):
		return 403
	case errors.Is(err, storage.ErrNotFound):
		return 404
	case errors.Is(err, security.ErrLocked):
		return 503
	default:
		return 500
	}
}
func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// A small global limiter bounds expensive password/unlock derivations. Reverse
// proxies can add per-source limits; forwarded source headers are not trusted.
func (s *Server) limit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.window) > time.Minute {
		s.window = time.Now()
		s.attempts = 0
	}
	s.attempts++
	return s.attempts <= 30
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.TLS == nil {
		write(w, 400, map[string]string{"error": "HTTPS required"})
		return
	}
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if r.URL.Path == "/audit" {
		http.Redirect(w, r, "/api/v1/admin/audit/download", http.StatusSeeOther)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css" || r.URL.Path == "/browse.js" {
		s.ui(w, r)
		return
	}
	if r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/ready" {
		if r.Method != "GET" {
			write(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		code := 200
		if r.URL.Path == "/api/v1/ready" && (s.Vault.Locked() || s.Store.Ping(r.Context()) != nil) {
			code = 503
		}
		write(w, code, map[string]bool{"ok": code == 200})
		return
	}
	// Reject cross-origin browser writes, including login where there is not yet
	// a session CSRF token. Authenticated writes additionally require the token.
	if r.Method != "GET" && r.Method != "HEAD" {
		if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
			write(w, 403, map[string]string{"error": "origin rejected"})
			return
		}
	}
	identity := "anonymous"
	path := ""
	op := r.Method + " " + r.URL.Path
	var result any
	code := 200
	var cookie *http.Cookie
	err := s.Store.Update(r.Context(), func(t storage.Tx) error {
		var e error
		result, code, cookie, e = s.route(t, r, &identity, &path)
		return e
	})
	// Audit metadata is recorded for both successful and failed API operations.
	// Use a fresh context so a disconnected caller cannot cancel its audit record.
	a := Audit{time.Now().UTC(), identity, path, op, err == nil, r.RemoteAddr}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := s.Store.Update(ctx, func(t storage.Tx) error {
		if e := t.Put("audit", time.Now().UTC().Format(time.RFC3339Nano)+"-"+security.Token(), a); e != nil {
			return e
		}
		// Identity verification is recorded independently of authorization: a valid
		// agent may authenticate successfully but still be denied the requested path.
		authentication := Audit{time.Now().UTC(), identity, "", "authentication", identity != "anonymous", r.RemoteAddr}
		return t.Put("audit", time.Now().UTC().Format(time.RFC3339Nano)+"-"+security.Token(), authentication)
	}); e != nil {
		s.Log.Error("audit persistence failed")
		err = errors.New("audit unavailable")
	}
	s.Log.Info("api request", "identity", identity, "operation", r.Method, "path", r.URL.Path, "success", err == nil, "source", r.RemoteAddr)
	if err != nil {
		code = status(err)
		message := err.Error()
		if code == 500 {
			message = "internal server error"
			s.Log.Error("request failed", "status", code)
		}
		write(w, code, map[string]string{"error": message})
		return
	}
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	if _, download := result.(auditDownload); download {
		s.downloadAudit(w, r)
		return
	}
	write(w, code, result)
}
func (s *Server) route(t storage.Tx, r *http.Request, identity, path *string) (any, int, *http.Cookie, error) {
	ok := func(v any) (any, int, *http.Cookie, error) { return v, 200, nil, nil }
	fail := func(e error) (any, int, *http.Cookie, error) { return nil, 0, nil, e }
	p := r.URL.Path
	if p == "/api/v1/login" && r.Method == "POST" {
		if !s.limit() {
			return fail(&apiError{429, "try again later"})
		}
		var in struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if e := decode(r, &in); e != nil {
			return fail(e)
		}
		var a Admin
		e := t.Get("admins", in.Name, &a)
		if e != nil || bcrypt.CompareHashAndPassword(a.Password, []byte(in.Password)) != nil {
			return fail(errUnauth)
		}
		*identity = "admin:" + a.Name
		token := security.Token()
		session := Session{security.Hash(token), a.Name, security.Token(), time.Now().Add(s.SessionTTL)}
		if e = t.Put("sessions", security.Hash(token), session); e != nil {
			return fail(e)
		}
		return session, 200, &http.Cookie{Name: "ssm_session", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.Expires}, nil
	}
	if p == "/api/v1/enroll" && r.Method == "POST" {
		if !s.limit() {
			return fail(&apiError{429, "try again later"})
		}
		var in struct {
			Token string `json:"token"`
		}
		if e := decode(r, &in); e != nil {
			return fail(e)
		}
		var en Enrollment
		if t.Get("enrollment", security.Hash(in.Token), &en) != nil || en.Used || !time.Now().Before(en.Expires) {
			return fail(errUnauth)
		}
		var a Agent
		if t.Get("agents", en.AgentID, &a) != nil || a.Revoked || a.Hash != "" {
			return fail(errUnauth)
		}
		token := security.Token()
		a.Hash = security.Hash(token)
		en.Used = true
		*identity = "agent:" + a.ID
		if e := t.Put("agents", a.ID, a); e != nil {
			return fail(e)
		}
		if e := t.Put("credentials", a.Hash, map[string]string{"ID": a.ID}); e != nil {
			return fail(e)
		}
		if e := t.Put("enrollment", en.Hash, en); e != nil {
			return fail(e)
		}
		return ok(map[string]string{"id": a.ID, "token": token})
	}
	if strings.HasPrefix(p, "/api/v1/admin/") {
		session, e := authenticateAdmin(t, r)
		if session.Admin != "" {
			*identity = "admin:" + session.Admin
		}
		if e != nil {
			return fail(e)
		}
		*identity = "admin:" + session.Admin
		if p == "/api/v1/admin/write-credentials" || strings.HasPrefix(p, "/api/v1/admin/write-credentials/") {
			value, e := manageWriteCredentials(t, r)
			if e != nil {
				return fail(e)
			}
			return ok(value)
		}
		switch p {
		case "/api/v1/admin/session":
			if r.Method == "GET" {
				return ok(session)
			}
		case "/api/v1/admin/logout":
			if r.Method == "POST" {
				c, _ := r.Cookie("ssm_session")
				if e = t.Delete("sessions", security.Hash(c.Value)); e != nil {
					return fail(e)
				}
				return map[string]bool{"ok": true}, 200, &http.Cookie{Name: "ssm_session", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1}, nil
			}
		case "/api/v1/admin/status":
			if r.Method == "GET" {
				return ok(map[string]any{"version": version.Version, "locked": s.Vault.Locked()})
			}
		case "/api/v1/admin/unlock":
			if r.Method == "POST" {
				if !s.limit() {
					return fail(&apiError{429, "try again later"})
				}
				var in struct {
					Master string `json:"master"`
				}
				if e = decode(r, &in); e != nil {
					return fail(e)
				}
				var en security.Envelope
				if e = t.Get("config", "envelope", &en); e != nil {
					return fail(e)
				}
				if e = s.Vault.Unlock(in.Master, en); e != nil {
					return fail(errUnauth)
				}
				return ok(map[string]bool{"locked": false})
			}
		case "/api/v1/admin/lock":
			if r.Method == "POST" {
				s.Vault.Lock()
				return ok(map[string]bool{"locked": true})
			}
		case "/api/v1/admin/master":
			if r.Method == "POST" {
				if !s.limit() {
					return fail(&apiError{429, "try again later"})
				}
				var in struct {
					Old string `json:"old"`
					New string `json:"new"`
				}
				if e = decode(r, &in); e != nil {
					return fail(e)
				}
				var en security.Envelope
				if e = t.Get("config", "envelope", &en); e != nil {
					return fail(e)
				}
				en, e = security.Rewrap(in.Old, in.New, en)
				if e != nil {
					return fail(bad("master key change failed; verify old key and new key length"))
				}
				if e = t.Put("config", "envelope", en); e != nil {
					return fail(e)
				}
				return ok(map[string]bool{"ok": true})
			}
		case "/api/v1/admin/secrets":
			if r.Method == "GET" {
				rows, e := t.List("secrets")
				if e != nil {
					return fail(e)
				}
				out := []Secret{}
				for _, b := range rows {
					var x Secret
					if e = json.Unmarshal(b, &x); e != nil {
						return fail(e)
					}
					if !x.Deleted {
						x.Ciphertext = nil
						out = append(out, x)
					}
				}
				return ok(out)
			}
		case "/api/v1/admin/agents":
			if r.Method == "GET" {
				rows, e := t.List("agents")
				if e != nil {
					return fail(e)
				}
				out := []Agent{}
				for _, b := range rows {
					var a Agent
					if e = json.Unmarshal(b, &a); e != nil {
						return fail(e)
					}
					a.Hash = ""
					out = append(out, a)
				}
				return ok(out)
			}
			if r.Method == "POST" {
				var in struct {
					Name  string   `json:"name"`
					Paths []string `json:"paths"`
				}
				if e = decode(r, &in); e != nil {
					return fail(e)
				}
				if in.Name == "" {
					return fail(bad("name required"))
				}
				if e = security.ValidateRules(in.Paths); e != nil {
					return fail(bad(e.Error()))
				}
				a := Agent{ID: security.Token(), Name: in.Name, Paths: in.Paths, Created: time.Now().UTC()}
				if e = t.Put("agents", a.ID, a); e != nil {
					return fail(e)
				}
				return ok(a)
			}
		case "/api/v1/admin/enrollment":
			if r.Method == "GET" {
				rows, e := t.List("enrollment")
				if e != nil {
					return fail(e)
				}
				out := []Enrollment{}
				for _, b := range rows {
					var en Enrollment
					if e = json.Unmarshal(b, &en); e != nil {
						return fail(e)
					}
					en.Hash = ""
					out = append(out, en)
				}
				return ok(out)
			}
			if r.Method == "POST" {
				var in struct {
					AgentID string `json:"agent_id"`
					TTL     int    `json:"ttl_seconds"`
				}
				if e = decode(r, &in); e != nil {
					return fail(e)
				}
				if in.TTL < 1 || in.TTL > 86400 {
					return fail(bad("TTL must be 1..86400 seconds"))
				}
				var a Agent
				if e = t.Get("agents", in.AgentID, &a); e != nil {
					return fail(e)
				}
				if a.Revoked || a.Hash != "" {
					return fail(bad("agent already enrolled or revoked"))
				}
				token := security.Token()
				en := Enrollment{security.Token(), a.ID, security.Hash(token), time.Now().Add(time.Duration(in.TTL) * time.Second), false}
				if e = t.Put("enrollment", en.Hash, en); e != nil {
					return fail(e)
				}
				return ok(map[string]any{"token": token, "enrollment": map[string]any{"id": en.ID, "agent_id": en.AgentID, "expires_at": en.Expires}})
			}
		case "/api/v1/admin/administrators":
			if r.Method == "GET" {
				rows, e := t.List("admins")
				if e != nil {
					return fail(e)
				}
				out := []string{}
				for _, b := range rows {
					var a Admin
					if e = json.Unmarshal(b, &a); e != nil {
						return fail(e)
					}
					out = append(out, a.Name)
				}
				return ok(out)
			}
			if r.Method == "POST" {
				var in struct {
					Name     string `json:"name"`
					Password string `json:"password"`
				}
				if e = decode(r, &in); e != nil {
					return fail(e)
				}
				if in.Name == "" || len(in.Password) < 12 {
					return fail(bad("name and password of at least 12 characters required"))
				}
				hash, e := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
				if e != nil {
					return fail(bad("invalid password length"))
				}
				if e = t.Put("admins", in.Name, Admin{in.Name, hash}); e != nil {
					return fail(e)
				}
				if e = deleteSessions(t, in.Name); e != nil {
					return fail(e)
				}
				return ok(map[string]bool{"ok": true})
			}
		case "/api/v1/admin/audit/download":
			if r.Method == "GET" {
				return ok(auditDownload{})
			}
		case "/api/v1/admin/audit":
			if r.Method == "GET" {
				rows, e := t.List("audit")
				if e != nil {
					return fail(e)
				}
				return ok(rows)
			}
		}
		if strings.HasPrefix(p, "/api/v1/admin/administrators/") && r.Method == "DELETE" {
			name := strings.TrimPrefix(p, "/api/v1/admin/administrators/")
			if name == session.Admin {
				return fail(bad("cannot delete your own administrator"))
			}
			if e = t.Delete("admins", name); e != nil {
				return fail(e)
			}
			if e = deleteSessions(t, name); e != nil {
				return fail(e)
			}
			return ok(map[string]bool{"ok": true})
		}
		if strings.HasPrefix(p, "/api/v1/admin/enrollment/") && r.Method == "DELETE" {
			id := strings.TrimPrefix(p, "/api/v1/admin/enrollment/")
			rows, e := t.List("enrollment")
			if e != nil {
				return fail(e)
			}
			for _, b := range rows {
				var en Enrollment
				if e = json.Unmarshal(b, &en); e != nil {
					return fail(e)
				}
				if en.ID == id {
					if e = t.Delete("enrollment", en.Hash); e != nil {
						return fail(e)
					}
					return ok(map[string]bool{"ok": true})
				}
			}
			return fail(storage.ErrNotFound)
		}
		if strings.HasPrefix(p, "/api/v1/admin/agents/") && strings.HasSuffix(p, "/purge") && r.Method == "DELETE" {
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/admin/agents/"), "/purge")
			if e = deleteAgent(t, id); e != nil {
				return fail(e)
			}
			return ok(map[string]bool{"ok": true})
		}
		if strings.HasPrefix(p, "/api/v1/admin/agents/") {
			id := strings.TrimPrefix(p, "/api/v1/admin/agents/")
			var a Agent
			if e = t.Get("agents", id, &a); e != nil {
				return fail(e)
			}
			if r.Method == "DELETE" {
				a.Revoked = true
				if a.Hash != "" {
					if e = t.Delete("credentials", a.Hash); e != nil {
						return fail(e)
					}
				}
			} else if r.Method == "PUT" {
				var in struct {
					Paths []string `json:"paths"`
				}
				if e = decode(r, &in); e != nil {
					return fail(e)
				}
				if e = security.ValidateRules(in.Paths); e != nil {
					return fail(bad(e.Error()))
				}
				a.Paths = in.Paths
			} else {
				return fail(&apiError{405, "method not allowed"})
			}
			if e = t.Put("agents", a.ID, a); e != nil {
				return fail(e)
			}
			a.Hash = ""
			return ok(a)
		}
		if strings.HasPrefix(p, "/api/v1/admin/secrets/") {
			*path = strings.TrimPrefix(p, "/api/v1/admin/secrets/")
			v, e := s.secret(t, r, *path, false)
			if e != nil {
				return fail(e)
			}
			return ok(v)
		}
		return fail(&apiError{405, "unknown route or method"})
	}
	if strings.HasPrefix(p, "/api/v1/write/") {
		value, e := s.writeSecret(t, r, identity, path)
		if e != nil {
			return fail(e)
		}
		return ok(value)
	}
	metadata := strings.HasPrefix(p, "/api/v1/metadata/")
	if metadata || strings.HasPrefix(p, "/api/v1/secrets/") {
		a, e := authenticateAgent(t, r)
		if e != nil {
			return fail(e)
		}
		*identity = "agent:" + a.ID
		prefix := "/api/v1/secrets/"
		if metadata {
			prefix = "/api/v1/metadata/"
		}
		*path = strings.TrimPrefix(p, prefix)
		normalized, e := security.Normalize(*path)
		if e != nil {
			return fail(bad(e.Error()))
		}
		*path = normalized
		if !security.Allowed(normalized, a.Paths) {
			return fail(errForbidden)
		}
		if r.Method != "GET" {
			return fail(errForbidden)
		}
		v, e := s.secret(t, r, normalized, metadata)
		if e != nil {
			return fail(e)
		}
		return ok(v)
	}
	return fail(&apiError{404, "not found"})
}

// Password changes and administrator deletion invalidate every existing session.
func deleteSessions(t storage.Tx, name string) error {
	rows, e := t.List("sessions")
	if e != nil {
		return e
	}
	for _, b := range rows {
		var session Session
		if e = json.Unmarshal(b, &session); e != nil {
			return e
		}
		if session.Admin == name {
			if e = t.Delete("sessions", session.Hash); e != nil {
				return e
			}
		}
	}
	return nil
}
