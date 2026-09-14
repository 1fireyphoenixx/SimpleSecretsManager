package security

import (
	"bytes"
	"testing"
)

func TestNormalizationAndAuthorization(t *testing.T) {
	for _, p := range []string{"servers/web01/password", "k8s/homelab/db", "one", "ü/key"} {
		if got, e := Normalize(p); e != nil || got != p {
			t.Fatalf("normalize %q: %v", p, e)
		}
	}
	for _, p := range []string{"", "/one", "one/", "a//b", "a/../b", "a/./b", "a\\b", "a/%2f/b", "a/*", "a\x00b", " a"} {
		if _, e := Normalize(p); e == nil {
			t.Errorf("accepted %q", p)
		}
	}
	rules := []string{"servers/web01/*", "k8s/homelab/*", "exact"}
	if e := ValidateRules(rules); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"servers/web01/password", "k8s/homelab/a/b", "exact"} {
		if !Allowed(p, rules) {
			t.Errorf("denied %q", p)
		}
	}
	for _, p := range []string{"servers/web010/password", "servers/web01", "k8s/other/x", "exact/child", "a/../exact"} {
		if Allowed(p, rules) {
			t.Errorf("allowed %q", p)
		}
	}
	if Allowed("exact", nil) {
		t.Fatal("not default-deny")
	}
	if ValidateRules([]string{"*"}) == nil {
		t.Fatal("accepted global wildcard")
	}
}
func TestEncryptionEnvelopeAndLock(t *testing.T) {
	master := "a strong master key for testing"
	en, e := NewEnvelope(master)
	if e != nil {
		t.Fatal(e)
	}
	key, e := Unwrap(master, en)
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("a secret value")
	a, e := Seal(key, plain, []byte("path"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := Seal(key, plain, []byte("path"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(a, b) {
		t.Fatal("nonce reused")
	}
	out, e := Open(key, a, []byte("path"))
	if e != nil || !bytes.Equal(out, plain) {
		t.Fatal("roundtrip failed")
	}
	if _, e = Open(key, a, []byte("other")); e == nil {
		t.Fatal("AAD not authenticated")
	}
	a[len(a)-1] ^= 1
	if _, e = Open(key, a, []byte("path")); e == nil {
		t.Fatal("tampering accepted")
	}
	if _, e = Unwrap("wrong", en); e == nil {
		t.Fatal("wrong master accepted")
	}
	rotated, e := Rewrap(master, "a different strong master key", en)
	if e != nil {
		t.Fatal(e)
	}
	key2, e := Unwrap("a different strong master key", rotated)
	if e != nil || !bytes.Equal(key, key2) {
		t.Fatal("rewrap changed DEK")
	}
	if _, e = Unwrap(master, rotated); e == nil {
		t.Fatal("old master accepted")
	}
	var v Vault
	if !v.Locked() {
		t.Fatal("must start locked")
	}
	if _, e = v.Encrypt("p", plain); e != ErrLocked {
		t.Fatal(e)
	}
	if e = v.Unlock(master, en); e != nil {
		t.Fatal(e)
	}
	blob, e := v.Encrypt("p", plain)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := v.Decrypt("p", blob); e != nil || !bytes.Equal(got, plain) {
		t.Fatal("vault roundtrip")
	}
	v.Lock()
	if _, e = v.Decrypt("p", blob); e != ErrLocked {
		t.Fatal(e)
	}
}
func TestRuntimeTokenRandomnessAndHash(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		token := Token()
		if len(token) != 43 || seen[token] {
			t.Fatal("invalid or repeated token")
		}
		seen[token] = true
		if Hash(token) == token || len(Hash(token)) != 64 {
			t.Fatal("bad hash")
		}
	}
}
