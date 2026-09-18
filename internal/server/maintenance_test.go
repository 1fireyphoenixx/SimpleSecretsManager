package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"simplesecretsmanager/internal/security"
	"simplesecretsmanager/internal/storage"
)

func TestDeleteAgentAndReuseName(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "agents.db"))
	f.login()
	id, token := f.enrollment([]string{"host/*"})
	extra := f.request("admin/enrollment", "POST", map[string]any{"agent_id": id, "ttl_seconds": 1}, "", 200)["token"].(string)
	runtime := f.request("enroll", "POST", map[string]string{"token": token}, "", 200)["token"].(string)
	other, otherToken := f.enrollment(nil)
	csrf := f.csrf
	f.csrf = ""
	f.request("admin/agents/"+id+"/purge", "DELETE", nil, "", 403)
	f.csrf = csrf
	// A bearer cannot use the administrator deletion endpoint.
	jar := f.client.Jar
	f.client.Jar = nil
	f.request("admin/agents/"+id+"/purge", "DELETE", nil, runtime, 401)
	f.client.Jar = jar
	f.request("admin/agents/"+id+"/purge", "DELETE", nil, "", 200)
	f.request("admin/agents/"+id+"/purge", "DELETE", nil, "", 404)
	f.request("enroll", "POST", map[string]string{"token": extra}, "", 401)
	f.request("enroll", "POST", map[string]string{"token": token}, "", 401)
	f.request("metadata/host/key", "GET", nil, runtime, 401)
	err := f.app.Store.Update(context.Background(), func(tx storage.Tx) error {
		for _, record := range [][2]string{{"agents", id}, {"credentials", security.Hash(runtime)}, {"enrollment", security.Hash(token)}, {"enrollment", security.Hash(extra)}} {
			var value any
			if e := tx.Get(record[0], record[1], &value); !errors.Is(e, storage.ErrNotFound) {
				t.Fatalf("record remains: %s %v", record[0], e)
			}
		}
		var a Agent
		return tx.Get("agents", other, &a)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.request("enroll", "POST", map[string]string{"token": otherToken}, "", 200)
	// The helper deliberately uses the same display name for every identity.
	replacement, replacementToken := f.enrollment(nil)
	if replacement == id {
		t.Fatal("replacement reused deleted identity")
	}
	f.request("enroll", "POST", map[string]string{"token": replacementToken}, "", 200)
	f.request("admin/agents/"+replacement, "DELETE", nil, "", 200)
	f.request("admin/agents/"+replacement+"/purge", "DELETE", nil, "", 200)
}

func TestAuditAttachment(t *testing.T) {
	f := newFixture(t, "sqlite", filepath.Join(t.TempDir(), "audit.db"))
	f.request("admin/audit/download", "GET", nil, "", 401)
	f.login()
	// More than two storage batches, while locked: audit export needs no DEK.
	if err := f.app.Store.Update(context.Background(), func(tx storage.Tx) error {
		for i := 0; i < 700; i++ {
			if err := tx.Put("audit", "fixture-"+security.Token(), Audit{Identity: "test-admin", Operation: "test-export", Success: true}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/admin/audit/download", nil)
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	if !strings.Contains(response.Header.Get("Content-Disposition"), "attachment;") || !strings.Contains(response.Header.Get("Content-Disposition"), ".txt") {
		t.Fatal("not an attachment")
	}
	if response.Header.Get("Content-Type") != "text/plain; charset=utf-8" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("incorrect download headers")
	}
	scanner := bufio.NewScanner(response.Body)
	count := 0
	for scanner.Scan() {
		var a Audit
		if err = json.Unmarshal(scanner.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		if a.Operation == "test-export" {
			count++
		}
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 700 {
		t.Fatalf("truncated download: %d", count)
	}
}
