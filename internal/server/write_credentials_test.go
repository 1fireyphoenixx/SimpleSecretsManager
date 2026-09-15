package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

// Exercise the public HTTPS boundary, not just the permission helper: cookies,
// agent tokens, scoped writer tokens, and revocation must stay independent.
func TestScopedWriteCredentials(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "writers.db"))
	f.request("admin/write-credentials", "POST", map[string]any{"name": "certbot", "paths": []string{"certificates/site/*"}}, "", 401)
	f.login()
	f.unlock()
	csrf := f.csrf
	f.csrf = ""
	f.request("admin/write-credentials", "POST", map[string]any{"name": "certbot"}, "", 403)
	f.csrf = csrf
	for _, paths := range [][]string{{"*"}, {"certificates/../*"}, {"certificates/*/key"}} {
		f.request("admin/write-credentials", "POST", map[string]any{"name": "bad", "paths": paths}, "", 400)
	}
	for _, path := range []string{"certificates/site/fullchain", "certificates/site/key", "certificates/site2/key", "exact"} {
		f.request("admin/secrets/"+path, "POST", map[string]string{"value": "original"}, "", 200)
	}
	created := f.request("admin/write-credentials", "POST", map[string]any{"name": "certbot", "paths": []string{"certificates/site/*", "exact"}}, "", 200)
	token := created["token"].(string)
	credential := created["credential"].(map[string]any)
	id := credential["id"].(string)
	if credential["credential_hash"] != nil {
		t.Fatal("creation exposes hash")
	}
	_, enrollment := f.enrollment([]string{"certificates/site/*"})
	agentToken := f.request("enroll", "POST", map[string]string{"token": enrollment}, "", 200)["token"].(string)
	// Bearer-only requests intentionally carry neither the admin cookie nor CSRF.
	jar := f.client.Jar
	f.client.Jar = nil
	f.csrf = ""
	body := map[string]string{"value": "writer-secret-sentinel"}
	f.request("write/certificates/site/key", "POST", body, "", 401)
	f.request("write/certificates/site/key", "POST", body, agentToken, 401)
	f.request("admin/write-credentials", "GET", nil, token, 401)
	f.request("secrets/certificates/site/key", "GET", nil, token, 401)
	f.request("metadata/certificates/site/key", "GET", nil, token, 401)
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		f.request("write/certificates/site/key", method, body, token, 405)
	}
	for _, path := range []string{"certificates/site2/key", "certificates/site", "exact/child"} {
		f.request("write/"+path, "POST", body, token, 403)
	}
	for _, path := range []string{"certificates/site/%2e%2e/site2/key", "certificates/site//key", "certificates/site/%252e%252e/key"} {
		f.request("write/"+path, "POST", body, token, 400)
	}
	f.request("write/certificates/site/missing", "POST", body, token, 404)
	f.request("write/certificates/site/key", "POST", map[string]string{}, token, 400)
	updated := f.request("write/certificates/site/key", "POST", body, token, 200)
	if updated["revision"] != float64(2) || updated["data"] != nil || updated["ciphertext"] != nil {
		t.Fatal("unexpected update response")
	}
	unchanged := f.request("write/certificates/site/key", "POST", body, token, 200)
	if unchanged["revision"] != float64(2) {
		t.Fatal("identical value advanced revision")
	}
	f.request("write/exact", "POST", body, token, 200)
	value := f.request("secrets/certificates/site/key", "GET", nil, agentToken, 200)
	if value["data"].(map[string]any)["value"] != body["value"] {
		t.Fatal("agent did not receive updated value")
	}
	f.app.Vault.Lock()
	f.request("write/certificates/site/key", "POST", body, token, 503)
	f.client.Jar = jar
	f.csrf = csrf
	f.unlock()
	// Listings never recover plaintext tokens or their stored hashes.
	res, e := f.client.Get(f.http.URL + "/api/v1/admin/write-credentials")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	if res.StatusCode != 200 || bytes.Contains(b, []byte(token)) || bytes.Contains(b, []byte("credential_hash")) {
		t.Fatal("unsafe listing")
	}
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"paths": []string{"certificates/site/fullchain"}}, "", 200)
	f.request("write/certificates/site/key", "POST", body, token, 403)
	f.request("write/certificates/site/fullchain", "POST", body, token, 200)
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"paths": []string{}}, "", 200)
	f.request("write/certificates/site/fullchain", "POST", body, token, 403)
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"paths": []string{"certificates/site/*"}}, "", 200)
	f.request("admin/secrets/certificates/site/key", "DELETE", nil, "", 200)
	f.request("write/certificates/site/key", "POST", body, token, 404)
	f.request("admin/write-credentials/"+id, "DELETE", nil, "", 200)
	f.request("write/certificates/site/fullchain", "POST", body, token, 401)
	// Permission editing must never resurrect a revoked credential.
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"paths": []string{"exact"}}, "", 200)
	f.request("write/exact", "POST", body, token, 401)
	if e = f.app.Store.Update(context.Background(), func(tx storage.Tx) error {
		var stored WriteCredential
		if e := tx.Get("writers", id, &stored); e != nil {
			return e
		}
		if stored.Hash != security.Hash(token) {
			t.Fatal("credential not hashed")
		}
		rows, e := tx.List("audit")
		if e != nil {
			return e
		}
		success, denied := false, false
		for _, row := range rows {
			var a Audit
			if e = json.Unmarshal(row, &a); e != nil {
				return e
			}
			if bytes.Contains(row, []byte(token)) || bytes.Contains(row, []byte(body["value"])) {
				t.Fatal("audit leaks credential/value")
			}
			if a.Identity == "writer:"+id && a.Operation == "POST /api/v1/write/certificates/site/key" && a.Path == "certificates/site/key" {
				success = success || a.Success
				denied = denied || !a.Success
			}
		}
		if !success || !denied {
			t.Fatal("missing writer audit outcomes")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(f.logs.String(), token) || strings.Contains(f.logs.String(), body["value"]) {
		t.Fatal("logs leak credential/value")
	}
}

// An existing database can save and reopen the new records without changing its
// SQL schema. Authentication still works after reconstructing the storage layer.
func TestWriterCredentialPersistence(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "persist.db")
	st, e := storage.Open(ctx, "sqlite", dsn)
	if e != nil {
		t.Fatal(e)
	}
	token := security.Token()
	c := WriteCredential{ID: security.Token(), Hash: security.Hash(token), Paths: []string{"a/*"}}
	e = st.Update(ctx, func(tx storage.Tx) error {
		if e := tx.Put("writers", c.ID, c); e != nil {
			return e
		}
		return tx.Put("writer_tokens", c.Hash, map[string]string{"ID": c.ID})
	})
	if e != nil {
		t.Fatal(e)
	}
	st.Close()
	st, e = storage.Open(ctx, "sqlite", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	req, _ := http.NewRequest("POST", "https://localhost/api/v1/write/a/b", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if e = st.Update(ctx, func(tx storage.Tx) error {
		got, e := authenticateWriter(tx, req)
		if e == nil && got.ID != c.ID {
			t.Fatal("wrong writer identity")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

// The existing POST is an upsert only when the administrator explicitly grants
// creation. The request body cannot grant itself additional privileges.
func TestWriterOptionalCreation(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "creation.db"))
	f.login()
	f.unlock()
	created := f.request("admin/write-credentials", "POST", map[string]any{"name": "creator", "paths": []string{"certs/site/*"}, "allow_create": true}, "", 200)
	token := created["token"].(string)
	id := created["credential"].(map[string]any)["id"].(string)
	if created["credential"].(map[string]any)["allow_create"] != true {
		t.Fatal("creation permission missing")
	}
	// Check the cookie-free curl flow as well as denied paths and invalid bodies.
	jar := f.client.Jar
	f.client.Jar = nil
	f.request("write/certs/site2/new", "POST", map[string]string{"value": "first"}, token, 403)
	f.request("write/certs/site/new", "POST", map[string]any{"value": "first", "allow_create": true}, token, 400)
	first := f.request("write/certs/site/new", "POST", map[string]string{"value": "first"}, token, 200)
	if first["revision"] != float64(1) || first["data"] != nil || first["ciphertext"] != nil {
		t.Fatal("unsafe creation response")
	}
	same := f.request("write/certs/site/new", "POST", map[string]string{"value": "first"}, token, 200)
	if same["revision"] != float64(1) {
		t.Fatal("identical POST is not idempotent")
	}
	changed := f.request("write/certs/site/new", "POST", map[string]string{"value": "second"}, token, 200)
	if changed["revision"] != float64(2) {
		t.Fatal("existing secret was not updated")
	}
	f.request("secrets/certs/site/new", "GET", nil, token, 401)
	f.request("write/certs/site/new", "DELETE", nil, token, 405)
	f.app.Vault.Lock()
	f.request("write/certs/site/locked", "POST", map[string]string{"value": "first"}, token, 503)
	f.client.Jar = jar
	f.unlock()
	f.request("admin/secrets/certs/site/locked", "GET", nil, "", 404)
	f.request("admin/secrets/certs/site/new", "DELETE", nil, "", 200)
	recreated := f.request("write/certs/site/new", "POST", map[string]string{"value": "third"}, token, 200)
	if recreated["revision"] != float64(3) {
		t.Fatal("recreation lost revision history")
	}
	// Omitted permissions survive edits, and toggling creation preserves paths.
	edit := f.request("admin/write-credentials/"+id, "PUT", map[string]any{"paths": []string{"certs/site/*"}}, "", 200)
	if edit["allow_create"] != true {
		t.Fatal("path edit cleared creation permission")
	}
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"allow_create": false}, "", 200)
	f.request("write/certs/site/missing", "POST", map[string]string{"value": "value"}, token, 404)
	f.request("write/certs/site/new", "POST", map[string]string{"value": "fourth"}, token, 200)
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"allow_create": true}, "", 200)
	f.request("write/certs/site/missing", "POST", map[string]string{"value": "value"}, token, 200)
	f.request("admin/write-credentials/"+id, "PUT", map[string]any{"paths": []string{}}, "", 200)
	f.request("write/certs/site/denied", "POST", map[string]string{"value": "value"}, token, 403)
	f.request("admin/write-credentials/"+id, "DELETE", nil, "", 200)
	f.request("write/certs/site/revoked", "POST", map[string]string{"value": "value"}, token, 401)
}

func TestLegacyWriterDefaultsToUpdateOnly(t *testing.T) {
	var legacy WriteCredential
	if err := json.Unmarshal([]byte(`{"id":"old","paths":["a/*"]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.AllowCreate {
		t.Fatal("legacy record gained creation permission")
	}
}
