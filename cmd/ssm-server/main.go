// ssm-server serves HTTPS, performs offline initial setup, and provides a CLI
// unlock client. Secret command-line arguments are intentionally not supported.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
	"simplesecretsmanager/internal/agent"
	"simplesecretsmanager/internal/server"
	"simplesecretsmanager/internal/storage"
	"simplesecretsmanager/internal/version"
)

type config struct {
	Listen     string `yaml:"listen"`
	Storage    string `yaml:"storage"`
	DSN        string `yaml:"dsn"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
	SessionTTL string `yaml:"session_ttl"`
	LogLevel   string `yaml:"log_level"`
}

func main() {
	if e := run(); e != nil {
		slog.Error("server stopped", "error", e)
		os.Exit(1)
	}
}
func readPrivate(path string) (string, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return "", errors.New("credential file unavailable")
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return "", errors.New("credential files must be regular and mode 0600")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", errors.New("credential file unreadable")
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
func run() error {
	v := flag.Bool("v", false, "print installed version")
	cfg := flag.String("config", "/etc/ssm-server/config.yaml", "server configuration")
	setup := flag.Bool("setup", false, "initialize database offline")
	unlock := flag.Bool("unlock", false, "unlock a running server using HTTPS")
	name := flag.String("admin", "admin", "administrator name for setup/unlock")
	passwordFile := flag.String("password-file", "", "0600 administrator password file")
	masterFile := flag.String("master-key-file", "", "0600 master key file")
	url := flag.String("server", "https://localhost:8443", "HTTPS origin for CLI unlock")
	ca := flag.String("ca-file", "", "private CA certificate for CLI unlock")
	flag.Parse()
	if *v {
		fmt.Println(version.Version)
		return nil
	}
	if *unlock {
		return unlockServer(*url, *ca, *name, *passwordFile, *masterFile)
	}
	c := config{Listen: ":8443", Storage: "sqlite", DSN: "/var/lib/ssm-server/ssm.db", SessionTTL: "8h", LogLevel: "info"}
	b, e := os.ReadFile(*cfg)
	if e != nil {
		return errors.New("cannot read server configuration")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return errors.New("invalid server configuration")
	}
	var level slog.Level
	if e = level.UnmarshalText([]byte(c.LogLevel)); e != nil {
		return errors.New("invalid log_level")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	ttl, e := time.ParseDuration(c.SessionTTL)
	if e != nil || ttl <= 0 {
		return errors.New("session_ttl must be positive")
	}
	// Restrict SQLite DB/WAL and any other newly created server files at source.
	syscall.Umask(0077)
	st, e := storage.Open(context.Background(), c.Storage, c.DSN)
	if e != nil {
		return errors.New("database open/migration failed")
	}
	defer st.Close()
	if *setup {
		password, e := readPrivate(*passwordFile)
		if e != nil {
			return e
		}
		master, e := readPrivate(*masterFile)
		if e != nil {
			return e
		}
		if e = server.Setup(context.Background(), st, *name, password, master); e != nil {
			return e
		}
		log.Info("initial setup complete; server will start locked")
		return nil
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		return errors.New("tls_cert and tls_key are required")
	}
	app := server.New(st, ttl, log)
	defer app.Vault.Lock()
	srv := &http.Server{ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn), Addr: c.Listen, Handler: app, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		log.Info("starting locked HTTPS server", "version", version.Version, "listen", c.Listen)
		done <- srv.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	}()
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("HTTPS listener failed")
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if e = srv.Shutdown(shutdown); e != nil {
			_ = srv.Close()
		}
		<-done
	}
	log.Info("server shutdown complete")
	return nil
}

// The CLI follows the same login + CSRF-protected unlock flow as the WebUI.
// File contents go only in HTTPS JSON request bodies and are never logged.
func unlockServer(origin, ca, name, passwordPath, masterPath string) error {
	if !strings.HasPrefix(origin, "https://") {
		return errors.New("HTTPS required")
	}
	client, e := agent.HTTPClient(ca)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	client.Jar, _ = cookiejar.New(nil)
	password, e := readPrivate(passwordPath)
	if e != nil {
		return e
	}
	master, e := readPrivate(masterPath)
	if e != nil {
		return e
	}
	call := func(path, csrf string, value any, out any) error {
		b, e := json.Marshal(value)
		if e != nil {
			return e
		}
		req, e := http.NewRequest("POST", strings.TrimRight(origin, "/")+"/api/v1/"+path, bytes.NewReader(b))
		if e != nil {
			return errors.New("invalid server URL")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		res, e := client.Do(req)
		if e != nil {
			return errors.New("HTTPS request failed")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("request failed: HTTP %d", res.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(out)
	}
	var session server.Session
	if e = call("login", "", map[string]string{"name": name, "password": password}, &session); e != nil {
		return e
	}
	var out any
	defer call("admin/logout", session.CSRF, map[string]string{}, &out)
	if e = call("admin/unlock", session.CSRF, map[string]string{"master": master}, &out); e != nil {
		return e
	}
	fmt.Println("SSM unlocked")
	return nil
}
