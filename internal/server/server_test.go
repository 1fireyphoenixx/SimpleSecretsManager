package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"simplesecretsmanager/internal/agent"
	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

const testPassword = "administrator-password-123"
const testMaster = "master-key-with-enough-entropy-for-test"

type fixture struct {
	t      *testing.T
	app    *Server
	http   *httptest.Server
	client *http.Client
	csrf   string
	logs   bytes.Buffer
	reads  atomic.Int64
}

func newFixture(t *testing.T, driver, dsn string) *fixture {
	t.Helper()
	st, e := storage.Open(context.Background(), driver, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	if e = Setup(context.Background(), st, "admin", testPassword, testMaster); e != nil {
		t.Fatal(e)
	}
	f := &fixture{t: t}
	f.app = New(st, time.Hour, slog.New(slog.NewJSONHandler(&f.logs, nil)))
	f.http = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") {
			f.reads.Add(1)
		}
		f.app.ServeHTTP(w, r)
	}))
	t.Cleanup(f.http.Close)
	f.client = f.http.Client()
	f.client.Jar, _ = cookiejar.New(nil)
	return f
}
func (f *fixture) request(path, method string, body any, token string, want int) map[string]any {
	f.t.Helper()
	b, _ := json.Marshal(body)
	req, e := http.NewRequest(method, f.http.URL+"/api/v1/"+path, bytes.NewReader(b))
	if e != nil {
		f.t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := f.client.Do(req)
	if e != nil {
		f.t.Fatal(e)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		f.t.Fatalf("%s %s: got %d want %d: %s", method, path, res.StatusCode, want, data)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		f.t.Fatal("missing no-store")
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}
func (f *fixture) login() {
	s := f.request("login", "POST", map[string]string{"name": "admin", "password": testPassword}, "", 200)
	f.csrf = s["csrf"].(string)
}
func (f *fixture) unlock() {
	f.request("admin/unlock", "POST", map[string]string{"master": testMaster}, "", 200)
}
func (f *fixture) enrollment(paths []string) (string, string) {
	a := f.request("admin/agents", "POST", map[string]any{"name": "test agent", "paths": paths}, "", 200)
	id := a["id"].(string)
	en := f.request("admin/enrollment", "POST", map[string]any{"agent_id": id, "ttl_seconds": 3600}, "", 200)
	return id, en["token"].(string)
}
func TestServerLifecycle(t *testing.T) {
	lifecycle(t, "sqlite", filepath.Join(t.TempDir(), "server.db"))
}
func TestMySQLServerLifecycle(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("MYSQL_TEST_DSN not set")
	}
	// This opt-in DSN is explicitly a disposable database. Leave storage
	// contract records alone because Go may run the storage package concurrently.
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec("DELETE FROM records WHERE kind <> 'test'")
	lifecycle(t, "mysql", dsn)
}
func lifecycle(t *testing.T, driver, dsn string) {
	f := newFixture(t, driver, dsn)
	f.request("health", "GET", nil, "", 200)
	f.request("ready", "GET", nil, "", 503)
	f.request("admin/status", "GET", nil, "", 401)
	f.request("login", "POST", map[string]string{"name": "admin", "password": "wrong"}, "", 401)
	f.login()
	csrf := f.csrf
	f.csrf = "wrong"
	f.request("admin/unlock", "POST", map[string]string{"master": testMaster}, "", 403)
	f.csrf = csrf
	f.request("admin/unlock", "POST", map[string]string{"master": "wrong"}, "", 401)
	f.unlock()
	f.request("ready", "GET", nil, "", 200)
	first := f.request("admin/secrets/servers/web01/password", "POST", map[string]string{"value": "secret-sentinel-991"}, "", 200)
	if first["revision"].(float64) != 1 {
		t.Fatal("first revision")
	}
	same := f.request("admin/secrets/servers/web01/password", "PUT", map[string]string{"value": "secret-sentinel-991"}, "", 200)
	if same["revision"].(float64) != 1 {
		t.Fatal("unchanged value increments revision")
	}
	updated := f.request("admin/secrets/servers/web01/password", "PUT", map[string]string{"value": "secret-sentinel-992"}, "", 200)
	if updated["revision"].(float64) != 2 {
		t.Fatal("update revision")
	}
	id, en := f.enrollment([]string{"servers/web01/*"})
	runtime := f.request("enroll", "POST", map[string]string{"token": en}, "", 200)["token"].(string)
	f.request("enroll", "POST", map[string]string{"token": en}, "", 401)
	f.request("secrets/servers/web01/password", "GET", nil, en, 401)
	v := f.request("secrets/servers/web01/password", "GET", nil, runtime, 200)
	if v["data"].(map[string]any)["value"] != "secret-sentinel-992" {
		t.Fatal("wrong value")
	}
	metadata := f.request("metadata/servers/web01/password", "GET", nil, runtime, 200)
	if metadata["data"] != nil || metadata["ciphertext"] != nil {
		t.Fatal("metadata exposes values")
	}
	f.request("secrets/servers/web010/password", "GET", nil, runtime, 403)
	f.request("secrets/servers/web01/missing", "GET", nil, runtime, 404)
	f.request("secrets/servers/web01/password", "PUT", map[string]string{"value": "bad"}, runtime, 403)
	f.request("secrets/servers/web01/%2e%2e/password", "GET", nil, runtime, 400)
	// A runtime bearer credential without the independent admin cookie cannot
	// access any administrative route, even if it can read a secret.
	jar := f.client.Jar
	f.client.Jar = nil
	f.request("admin/status", "GET", nil, runtime, 401)
	f.client.Jar = jar
	f.request("admin/agents/"+id, "PUT", map[string]any{"paths": []string{"k8s/homelab/*"}}, "", 200)
	f.request("secrets/servers/web01/password", "GET", nil, runtime, 403)
	f.request("admin/agents/"+id, "DELETE", nil, "", 200)
	f.request("metadata/k8s/homelab/password", "GET", nil, runtime, 401)
	// Expiration is checked atomically at redemption, without waiting in the test.
	_, expired := f.enrollment(nil)
	if e := f.app.Store.Update(context.Background(), func(tx storage.Tx) error {
		var en Enrollment
		if e := tx.Get("enrollment", security.Hash(expired), &en); e != nil {
			return e
		}
		en.Expires = time.Now().Add(-time.Second)
		return tx.Put("enrollment", en.Hash, en)
	}); e != nil {
		t.Fatal(e)
	}
	f.request("enroll", "POST", map[string]string{"token": expired}, "", 401)
	var before Secret
	if e := f.app.Store.Update(context.Background(), func(tx storage.Tx) error { return tx.Get("secrets", "servers/web01/password", &before) }); e != nil {
		t.Fatal(e)
	}
	f.request("admin/master", "POST", map[string]string{"old": testMaster, "new": "new-master-key-long-enough-123"}, "", 200)
	var after Secret
	if e := f.app.Store.Update(context.Background(), func(tx storage.Tx) error { return tx.Get("secrets", "servers/web01/password", &after) }); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before.Ciphertext, after.Ciphertext) {
		t.Fatal("rewrap changed secret ciphertext")
	}
	f.request("admin/lock", "POST", nil, "", 200)
	f.request("admin/secrets/servers/web01/password", "GET", nil, "", 503)
	f.request("health", "GET", nil, "", 200)
	f.request("admin/unlock", "POST", map[string]string{"master": testMaster}, "", 401)
	f.request("admin/unlock", "POST", map[string]string{"master": "new-master-key-long-enough-123"}, "", 200)
	f.request("admin/secrets/servers/web01/password", "DELETE", nil, "", 200)
	f.request("admin/secrets/servers/web01/password", "GET", nil, "", 404)
	recreated := f.request("admin/secrets/servers/web01/password", "POST", map[string]string{"value": "replacement"}, "", 200)
	if recreated["revision"].(float64) != 3 {
		t.Fatal("recreated secret reused revision")
	}
	if !New(f.app.Store, time.Hour, slog.Default()).Vault.Locked() {
		t.Fatal("restarted server unlocked")
	}
	// Database and structured audit/log output must not contain source values or
	// plaintext authentication material. Decrypted API responses are excluded.
	if e := f.app.Store.Update(context.Background(), func(tx storage.Tx) error {
		for _, kind := range []string{"secrets", "agents", "credentials", "enrollment", "audit", "sessions", "config"} {
			rows, e := tx.List(kind)
			if e != nil {
				return e
			}
			for _, b := range rows {
				for _, s := range []string{testPassword, testMaster, runtime, en, "secret-sentinel-991", "secret-sentinel-992"} {
					if bytes.Contains(b, []byte(s)) {
						t.Errorf("plaintext leaked in %s", kind)
					}
				}
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	f.request("admin/logout", "POST", nil, "", 200)
	f.request("admin/status", "GET", nil, "", 401)
	for _, s := range []string{testPassword, testMaster, runtime, en, "secret-sentinel-991", "secret-sentinel-992"} {
		if strings.Contains(f.logs.String(), s) {
			t.Fatal("plaintext in logs")
		}
	}
}
func TestAgentServerSynchronization(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "server.db"))
	f.login()
	f.unlock()
	f.request("admin/secrets/servers/web01/password", "POST", map[string]string{"value": "first"}, "", 200)
	_, en := f.enrollment([]string{"servers/web01/*"})
	root := t.TempDir()
	state := filepath.Join(root, "state")
	defs := filepath.Join(root, "definitions")
	templates := filepath.Join(root, "templates")
	for _, p := range []string{state, defs, templates} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	dest := filepath.Join(root, "deployed")
	raw := filepath.Join(root, "raw")
	hook := filepath.Join(root, "hook")
	templated := "path: servers/web01/password\ntemplate: config.templ\ndestination: " + dest + "\ncommand: [/bin/sh, -c, 'cat " + dest + " > " + hook + "']\n"
	if e := os.WriteFile(filepath.Join(defs, "config.yaml"), []byte(templated), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(defs, "raw.yaml"), []byte("path: servers/web01/password\ndestination: "+raw+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(templates, "config.templ"), []byte("value={{.Value}}"), 0600); e != nil {
		t.Fatal(e)
	}
	c := agent.Config{Server: f.http.URL, PollInterval: "1s", StateDir: state, SecretsDir: defs, TemplatesDir: templates, EnrollmentToken: en}
	a, e := agent.New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	a.Client = f.http.Client()
	if e = a.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	assertFile := func(p, want string) {
		t.Helper()
		b, e := os.ReadFile(p)
		if e != nil || string(b) != want {
			t.Fatalf("file %s: %q %v", p, b, e)
		}
	}
	assertFile(dest, "value=first")
	assertFile(raw, "first")
	assertFile(hook, "value=first")
	reads := f.reads.Load()
	if e = a.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.reads.Load() != reads {
		t.Fatal("unchanged values downloaded")
	}
	st, _ := os.Stat(filepath.Join(state, "credentials.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("insecure credential mode")
	}
	// A fresh agent process loads runtime credentials and revisions; it does not
	// attempt to redeem the already consumed initial enrollment token.
	a, e = agent.New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	a.Client = f.http.Client()
	if e = a.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.reads.Load() != reads {
		t.Fatal("restart lost revision state")
	}
	// Simulate a transport outage without altering persisted state or files.
	workingClient := a.Client
	a.Client = &http.Client{Transport: unavailableTransport{}}
	if e = a.Sync(context.Background()); e == nil {
		t.Fatal("outage should fail")
	}
	assertFile(dest, "value=first")
	a.Client = workingClient
	// Local mode drift is repaired even when the server revision is unchanged.
	if e = os.Chmod(dest, 0644); e != nil {
		t.Fatal(e)
	}
	if e = a.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	repaired, _ := os.Stat(dest)
	if repaired.Mode().Perm() != 0600 {
		t.Fatal("mode drift not repaired")
	}
	f.app.Vault.Lock()
	if e = a.Sync(context.Background()); e == nil {
		t.Fatal("locked server should fail synchronization")
	}
	assertFile(dest, "value=first")
	f.unlock()
	// Run the real polling loop and verify that a scoped writer update reaches
	// both files, including the template and the local post-change hook.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); <-done }()
	writer := f.request("admin/write-credentials", "POST", map[string]any{"name": "automation", "paths": []string{"servers/web01/password"}}, "", 200)
	f.request("write/servers/web01/password", "POST", map[string]string{"value": "second"}, writer["token"].(string), 200)
	deadline := time.Now().Add(6 * time.Second)
	for {
		b, _ := os.ReadFile(hook)
		r, _ := os.ReadFile(raw)
		if string(b) == "value=second" && string(r) == "second" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic synchronization timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	assertFile(dest, "value=second")
}
func TestEnrollmentRaceAndSessionExpiry(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "server.db"))
	f.login()
	_, en := f.enrollment(nil)
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, _ := json.Marshal(map[string]string{"token": en})
			res, e := f.client.Post(f.http.URL+"/api/v1/enroll", "application/json", bytes.NewReader(b))
			if e != nil {
				t.Error(e)
				return
			}
			defer res.Body.Close()
			if res.StatusCode == 200 {
				wins.Add(1)
			} else if res.StatusCode != 401 {
				t.Errorf("unexpected %d", res.StatusCode)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("redemptions: %d", wins.Load())
	}
	f.app.SessionTTL = -time.Second
	f.login()
	f.request("admin/status", "GET", nil, "", 401)
}
func TestTLSOriginAndVisibleVersion(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "server.db"))
	req := httptest.NewRequest("GET", "http://localhost/api/v1/health", nil)
	w := httptest.NewRecorder()
	f.app.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatal("HTTP allowed")
	}
	r, e := f.client.Get(f.http.URL + "/")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !bytes.Contains(b, []byte("SSM v0.0.3")) || !bytes.Contains(b, []byte("<header>")) {
		t.Fatal("persistent version missing")
	}
	req, _ = http.NewRequest("POST", f.http.URL+"/api/v1/login", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://evil.invalid")
	r, e = f.client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("cross-origin login allowed")
	}
}

type unavailableTransport struct{}

func (unavailableTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("test outage")
}

func TestAdministratorManagement(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "admins.db"))
	f.login()
	f.request("admin/administrators", "POST", map[string]string{"name": "second", "password": testPassword}, "", 200)
	f.request("admin/administrators/admin", "DELETE", nil, "", 400)
	f.request("admin/administrators/second", "DELETE", nil, "", 200)
	f.request("admin/administrators", "POST", map[string]string{"name": "admin", "password": "replacement-password-123"}, "", 200)
	f.request("admin/status", "GET", nil, "", 401)
	f.request("login", "POST", map[string]string{"name": "admin", "password": testPassword}, "", 401)
	f.request("login", "POST", map[string]string{"name": "admin", "password": "replacement-password-123"}, "", 200)
}
