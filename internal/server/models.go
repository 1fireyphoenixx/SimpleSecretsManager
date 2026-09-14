package server

import "time"

// Secret stores all metadata alongside authenticated ciphertext. Deleted records
// remain as tombstones so recreation cannot reuse an earlier revision number.
type Secret struct {
	Path       string    `json:"path"`
	Revision   int64     `json:"revision"`
	Created    time.Time `json:"created_at"`
	Updated    time.Time `json:"updated_at"`
	Ciphertext []byte    `json:"ciphertext,omitempty"`
	Algorithm  string    `json:"algorithm"`
	Deleted    bool      `json:"deleted,omitempty"`
}
type Agent struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Paths   []string  `json:"paths"`
	Hash    string    `json:"credential_hash,omitempty"`
	Revoked bool      `json:"revoked"`
	Created time.Time `json:"created_at"`
}
type Enrollment struct {
	ID      string    `json:"id"`
	AgentID string    `json:"agent_id"`
	Hash    string    `json:"token_hash,omitempty"`
	Expires time.Time `json:"expires_at"`
	Used    bool      `json:"used"`
}
type Admin struct {
	Name     string `json:"name"`
	Password []byte `json:"password_hash,omitempty"`
}
type Session struct {
	Hash    string    `json:"session_id"`
	Admin   string    `json:"admin"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires_at"`
}

// Audit deliberately has no free-form request body or credential field.
type Audit struct {
	Time      time.Time `json:"timestamp"`
	Identity  string    `json:"identity"`
	Path      string    `json:"path,omitempty"`
	Operation string    `json:"operation"`
	Success   bool      `json:"success"`
	Source    string    `json:"source"`
}
