package main

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"simplesecretsmanager/internal/server"
	"simplesecretsmanager/internal/storage"
)

// The CLI must use normal administrator authentication, verified private-CA TLS,
// and a CSRF token. It must not require a separate privileged unlock endpoint.
func TestCLIUnlock(t *testing.T) {
	dir := t.TempDir()
	st, e := storage.Open(context.Background(), "sqlite", filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	master := "a sufficiently strong CLI test master"
	password := "a sufficiently strong CLI test password"
	if e = server.Setup(context.Background(), st, "admin", password, master); e != nil {
		t.Fatal(e)
	}
	app := server.New(st, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	http := httptest.NewTLSServer(app)
	defer http.Close()
	ca := filepath.Join(dir, "ca.crt")
	pass := filepath.Join(dir, "password")
	key := filepath.Join(dir, "master")
	for path, b := range map[string][]byte{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: http.Certificate().Raw}), pass: []byte(password), key: []byte(master)} {
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = unlockServer(http.URL, ca, "admin", pass, key); e != nil {
		t.Fatal(e)
	}
	if app.Vault.Locked() {
		t.Fatal("CLI did not unlock")
	}
	if e = unlockServer("http://localhost", ca, "admin", pass, key); e == nil {
		t.Fatal("CLI allowed HTTP")
	}
	if e = os.Chmod(pass, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = readPrivate(pass); e == nil {
		t.Fatal("insecure input accepted")
	}
}
