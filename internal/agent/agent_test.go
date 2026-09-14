package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestTemplateRendering(t *testing.T) {
	b, e := Render("{{.Path}}={{.Value}} ({{.Revision}})", "hello", "a/b", 3)
	if e != nil || string(b) != "a/b=hello (3)" {
		t.Fatalf("%s %v", b, e)
	}
	if _, e = Render("{{.Missing}}", "s", "p", 1); e == nil {
		t.Fatal("missing field accepted")
	}
	if _, e = Render("{{", "s", "p", 1); e == nil {
		t.Fatal("invalid template accepted")
	}
}
func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	a := bytes.Repeat([]byte("a"), 100000)
	b := bytes.Repeat([]byte("b"), 100000)
	if e := AtomicWrite(path, a, 0600, -1, -1); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("insecure mode")
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				data, e := os.ReadFile(path)
				if e != nil || (!bytes.Equal(data, a) && !bytes.Equal(data, b)) {
					t.Error("observed partial file")
					return
				}
			}
		}
	}()
	for i := 0; i < 20; i++ {
		data := a
		if i%2 == 0 {
			data = b
		}
		if e := AtomicWrite(path, data, 0600, -1, -1); e != nil {
			t.Error(e)
			break
		}
	}
	close(done)
	wg.Wait()
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(link, b, 0600, -1, -1); e == nil {
		t.Fatal("destination symlink accepted")
	}
	parent := filepath.Join(dir, "parent")
	if e := os.Symlink(dir, parent); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(filepath.Join(parent, "new"), b, 0600, -1, -1); e == nil {
		t.Fatal("parent symlink accepted")
	}
	if e := AtomicWrite(filepath.Join(dir, "missing", "new"), b, 0600, -1, -1); e == nil {
		t.Fatal("missing parent accepted")
	}
}
func TestDefaultsAndCredentials(t *testing.T) {
	if mode, e := parseMode(""); e != nil || mode != 0600 {
		t.Fatal("default mode")
	}
	for _, s := range []string{"9999", "-1", "4755"} {
		if _, e := parseMode(s); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "cred")
	if e := os.WriteFile(p, []byte("credential"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := privateRead(p); e == nil {
		t.Fatal("insecure credentials accepted")
	}
	if _, e := New(Config{Server: "http://localhost", PollInterval: "1s"}, slog.Default()); e == nil {
		t.Fatal("HTTP accepted")
	}
}
func TestFailedHookRemainsPending(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{Config: Config{StateDir: dir}, state: map[string]Applied{"s": {Revision: 2, PendingCommand: true}}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if e := a.runCommand(context.Background(), "s", Definition{Command: []string{"/bin/false"}}); e == nil {
		t.Fatal("expected hook failure")
	}
	if !a.state["s"].PendingCommand {
		t.Fatal("lost pending hook")
	}
	if e := a.runCommand(context.Background(), "s", Definition{Command: []string{"/bin/true"}}); e != nil {
		t.Fatal(e)
	}
	if a.state["s"].PendingCommand {
		t.Fatal("hook not completed")
	}
}
