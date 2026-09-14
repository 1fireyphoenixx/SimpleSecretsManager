package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

var errUnauth = errors.New("authentication required")
var errForbidden = errors.New("permission denied")

// authenticateAdmin accepts only the secure session cookie. Bearer credentials
// are intentionally never considered here, even if an agent has broad paths.
func authenticateAdmin(t storage.Tx, r *http.Request) (Session, error) {
	c, e := r.Cookie("ssm_session")
	if e != nil {
		return Session{}, errUnauth
	}
	var s Session
	if e = t.Get("sessions", security.Hash(c.Value), &s); e != nil || !time.Now().Before(s.Expires) {
		return Session{}, errUnauth
	}
	var a Admin
	if t.Get("admins", s.Admin, &a) != nil {
		return Session{}, errUnauth
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			return s, errForbidden
		}
	}
	return s, nil
}

// authenticateAgent verifies identity only; authorization is a separate call to
// security.Allowed at the route where the requested normalized path is known.
func authenticateAgent(t storage.Tx, r *http.Request) (Agent, error) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || token == r.Header.Get("Authorization") {
		return Agent{}, errUnauth
	}
	var index struct{ ID string }
	if t.Get("credentials", security.Hash(token), &index) != nil {
		return Agent{}, errUnauth
	}
	var a Agent
	if t.Get("agents", index.ID, &a) != nil || a.Revoked || subtle.ConstantTimeCompare([]byte(a.Hash), []byte(security.Hash(token))) != 1 {
		return Agent{}, errUnauth
	}
	return a, nil
}
