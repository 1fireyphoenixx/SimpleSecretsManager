// Package security keeps identity verification, path authorization, and
// encryption separate. An authenticated identity is not automatically authorized.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/scrypt"
)

// Token creates a 256-bit bearer credential. Only its hash belongs in the DB.
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Normalize rejects ambiguous paths instead of silently granting access to a
// different resource. API routing performs URL decoding once, before this check.
func Normalize(p string) (string, error) {
	if p == "" || len(p) > 512 || strings.TrimSpace(p) != p || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\%*?") {
		return "", errors.New("invalid secret path")
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return "", errors.New("invalid secret path")
		}
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("invalid secret path")
		}
	}
	return p, nil
}

// ValidateRules permits exact paths and a terminal /* subtree match only.
func ValidateRules(rules []string) error {
	for _, r := range rules {
		if _, err := Normalize(strings.TrimSuffix(r, "/*")); err != nil {
			return err
		}
	}
	return nil
}

// Allowed is default-deny. A subtree rule requires the slash boundary, so a
// grant on servers/web01/* never grants servers/web010/password.
func Allowed(path string, rules []string) bool {
	p, err := Normalize(path)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if strings.HasSuffix(rule, "/*") {
			if strings.HasPrefix(p, strings.TrimSuffix(rule, "*")) {
				return true
			}
		} else if p == rule {
			return true
		}
	}
	return false
}

// Seal uses a new random 96-bit nonce for every AES-256-GCM encryption. AAD binds
// ciphertext to its logical record, preventing copies between secret paths.
func Seal(key, plain, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, plain, aad), nil
}
func Open(key, blob, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
}

// Envelope is persisted; it contains no plaintext keys. The master passphrase
// derives a wrapping key with scrypt and a per-envelope random salt.
type Envelope struct {
	Salt    []byte `json:"salt"`
	Wrapped []byte `json:"wrapped"`
}

func wrappingKey(master string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(master), salt, 32768, 8, 1, 32)
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func Wrap(master string, dek []byte) (Envelope, error) {
	if len(master) < 16 {
		return Envelope{}, errors.New("master key must have at least 16 characters")
	}
	salt := make([]byte, 32)
	if _, e := rand.Read(salt); e != nil {
		return Envelope{}, e
	}
	k, e := wrappingKey(master, salt)
	if e != nil {
		return Envelope{}, e
	}
	defer wipe(k)
	b, e := Seal(k, dek, []byte("ssm:dek:v1"))
	return Envelope{salt, b}, e
}
func Unwrap(master string, en Envelope) ([]byte, error) {
	k, e := wrappingKey(master, en.Salt)
	if e != nil {
		return nil, e
	}
	defer wipe(k)
	return Open(k, en.Wrapped, []byte("ssm:dek:v1"))
}
func NewEnvelope(master string) (Envelope, error) {
	k := make([]byte, 32)
	if _, e := rand.Read(k); e != nil {
		return Envelope{}, e
	}
	defer wipe(k)
	return Wrap(master, k)
}

var ErrLocked = errors.New("server is locked")

// Vault owns the only long-lived plaintext DEK. Its lock prevents a lock/unlock
// operation racing an encryption operation; callers never receive the key.
type Vault struct {
	mu  sync.RWMutex
	key []byte
}

func (v *Vault) Locked() bool { v.mu.RLock(); defer v.mu.RUnlock(); return len(v.key) == 0 }
func (v *Vault) Lock()        { v.mu.Lock(); defer v.mu.Unlock(); wipe(v.key); v.key = nil }
func (v *Vault) Unlock(master string, en Envelope) error {
	k, e := Unwrap(master, en)
	if e != nil {
		return errors.New("invalid unlock key")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	wipe(v.key)
	v.key = k
	return nil
}
func (v *Vault) Encrypt(p string, value []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.key) == 0 {
		return nil, ErrLocked
	}
	return Seal(v.key, value, []byte(p))
}
func (v *Vault) Decrypt(p string, b []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.key) == 0 {
		return nil, ErrLocked
	}
	return Open(v.key, b, []byte(p))
}

// Rewrap verifies the old key and creates a new envelope. Secret ciphertexts
// are untouched, so changing the master key does not rewrite the secret table.
func Rewrap(old, new string, en Envelope) (Envelope, error) {
	k, e := Unwrap(old, en)
	if e != nil {
		return Envelope{}, errors.New("invalid unlock key")
	}
	defer wipe(k)
	return Wrap(new, k)
}
