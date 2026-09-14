// Package agent enrolls once and periodically reconciles locally defined files.
// The server supplies values and metadata only, never destinations or commands.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
	"simplesecretsmanager/internal/security"
)

type Config struct {
	Server          string `yaml:"server"`
	CAFile          string `yaml:"ca_file"`
	EnrollmentToken string `yaml:"enrollment_token"`
	PollInterval    string `yaml:"poll_interval"`
	StateDir        string `yaml:"state_dir"`
	TemplatesDir    string `yaml:"templates_dir"`
	SecretsDir      string `yaml:"secrets_dir"`
	LogLevel        string `yaml:"log_level"`
}
type Definition struct {
	Path           string   `yaml:"path"`
	Template       string   `yaml:"template"`
	Destination    string   `yaml:"destination"`
	Owner          string   `yaml:"owner"`
	Group          string   `yaml:"group"`
	Mode           string   `yaml:"mode"`
	Command        []string `yaml:"command"`
	CommandTimeout string   `yaml:"command_timeout"`
}
type Credentials struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// Applied also remembers local configuration and output digests. This repairs
// missing/modified files and reapplies template changes even at the same revision.
// PendingCommand makes an interrupted/failed hook retry on the next poll.
type Applied struct {
	Revision       int64  `json:"revision"`
	Fingerprint    string `json:"fingerprint"`
	OutputHash     string `json:"output_hash"`
	PendingCommand bool   `json:"pending_command"`
}
type Agent struct {
	Config      Config
	Client      *http.Client
	Log         *slog.Logger
	credentials Credentials
	state       map[string]Applied
	interval    time.Duration
}

func randomName() string { return security.Token() }
func LoadConfig(path string) (Config, error) {
	c := Config{PollInterval: "30s", StateDir: "/var/lib/ssm-agent", TemplatesDir: "/etc/ssm-agent/templates", SecretsDir: "/etc/ssm-agent/secrets", LogLevel: "info"}
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	e = d.Decode(&c)
	return c, e
}

// HTTPClient always verifies TLS, including with a private CA. Redirects are
// rejected so credentials cannot be forwarded to another origin or plain HTTP.
func HTTPClient(caFile string) (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		b, e := os.ReadFile(caFile)
		if e != nil {
			return nil, e
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}, nil
}
func New(c Config, log *slog.Logger) (*Agent, error) {
	u, e := url.Parse(c.Server)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("server must be an HTTPS origin")
	}
	c.Server = strings.TrimRight(c.Server, "/")
	interval, e := time.ParseDuration(c.PollInterval)
	if e != nil || interval < time.Second {
		return nil, errors.New("poll_interval must be at least 1s")
	}
	client, e := HTTPClient(c.CAFile)
	if e != nil {
		return nil, e
	}
	if !filepath.IsAbs(c.StateDir) {
		return nil, errors.New("state_dir must be absolute")
	}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(c.StateDir)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be a real directory with mode 0700")
	}
	a := &Agent{Config: c, Client: client, Log: log, state: map[string]Applied{}, interval: interval}
	if b, e := privateRead(filepath.Join(c.StateDir, "credentials.json")); e == nil {
		if e = json.Unmarshal(b, &a.credentials); e != nil {
			return nil, errors.New("invalid credentials state")
		}
		if a.credentials.ID == "" || a.credentials.Token == "" {
			return nil, errors.New("empty credentials state")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if b, e := privateRead(filepath.Join(c.StateDir, "revisions.json")); e == nil {
		if e = json.Unmarshal(b, &a.state); e != nil {
			return nil, errors.New("invalid revision state")
		}
		if a.state == nil {
			a.state = map[string]Applied{}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	return a, nil
}

// Private state is never read through a symlink or from a group/world-readable
// file. AtomicWrite applies the same checks when saving replacement state.
func privateRead(path string) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state file must be regular with mode 0600")
	}
	return os.ReadFile(path)
}
func (a *Agent) request(ctx context.Context, path, method string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		reader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, a.Config.Server+"/api/v1/"+path, reader)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if a.credentials.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.credentials.Token)
	}
	res, e := a.Client.Do(req)
	if e != nil {
		return errors.New("server connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("server returned HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 3<<20)).Decode(out)
}
func (a *Agent) Enroll(ctx context.Context) error {
	if a.credentials.Token != "" {
		a.Config.EnrollmentToken = ""
		return nil
	}
	if a.Config.EnrollmentToken == "" {
		return errors.New("enrollment token required")
	}
	var c Credentials
	if e := a.request(ctx, "enroll", "POST", map[string]string{"token": a.Config.EnrollmentToken}, &c); e != nil {
		return e
	}
	if c.ID == "" || c.Token == "" {
		return errors.New("invalid enrollment response")
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	if e = AtomicWrite(filepath.Join(a.Config.StateDir, "credentials.json"), b, 0600, -1, -1); e != nil {
		return errors.New("could not persist runtime credential; create a new agent enrollment")
	}
	a.credentials = c
	a.Config.EnrollmentToken = ""
	a.Log.Info("enrolled", "agent_id", c.ID)
	return nil
}
func Render(source, value, path string, revision int64) ([]byte, error) {
	t, e := template.New("secret").Option("missingkey=error").Parse(source)
	if e != nil {
		return nil, errors.New("invalid template")
	}
	var b bytes.Buffer
	e = t.Execute(&b, struct {
		Value    string
		Path     string
		Revision int64
	}{value, path, revision})
	if e != nil {
		return nil, errors.New("template rendering failed")
	}
	return b.Bytes(), nil
}
func (a *Agent) save() error {
	b, e := json.Marshal(a.state)
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(a.Config.StateDir, "revisions.json"), b, 0600, -1, -1)
}
func id(s string, group bool) (int, error) {
	if s == "" {
		return -1, nil
	}
	if n, e := strconv.Atoi(s); e == nil {
		if n < 0 {
			return 0, errors.New("owner/group must be nonnegative")
		}
		return n, nil
	}
	var n string
	if group {
		g, e := user.LookupGroup(s)
		if e != nil {
			return 0, errors.New("unknown group")
		}
		n = g.Gid
	} else {
		u, e := user.Lookup(s)
		if e != nil {
			return 0, errors.New("unknown owner")
		}
		n = u.Uid
	}
	return strconv.Atoi(n)
}
func (a *Agent) definitions() (map[string]Definition, error) {
	entries, e := os.ReadDir(a.Config.SecretsDir)
	if e != nil {
		return nil, e
	}
	out := map[string]Definition{}
	destinations := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("definition symlinks are forbidden")
		}
		b, e := os.ReadFile(filepath.Join(a.Config.SecretsDir, entry.Name()))
		if e != nil {
			return nil, e
		}
		var d Definition
		decoder := yaml.NewDecoder(bytes.NewReader(b))
		decoder.KnownFields(true)
		if e = decoder.Decode(&d); e != nil {
			return nil, errors.New("invalid secret definition")
		}
		if _, e = security.Normalize(d.Path); e != nil {
			return nil, e
		}
		if !filepath.IsAbs(d.Destination) || filepath.Clean(d.Destination) != d.Destination || d.Destination == "/" {
			return nil, errors.New("destination must be a clean absolute path")
		}
		if destinations[d.Destination] {
			return nil, errors.New("duplicate destination")
		}
		destinations[d.Destination] = true
		// Prevent accidental replacement of the agent's own credentials/configuration.
		for _, dir := range []string{a.Config.StateDir, a.Config.TemplatesDir, a.Config.SecretsDir, "/etc/ssm-agent"} {
			clean := filepath.Clean(dir)
			if d.Destination == clean || strings.HasPrefix(d.Destination, clean+"/") {
				return nil, errors.New("destination overlaps agent configuration or state")
			}
		}
		if d.Template != "" && (filepath.Base(d.Template) != d.Template || !strings.HasSuffix(d.Template, ".templ")) {
			return nil, errors.New("template must be a .templ basename")
		}
		if len(d.Command) > 0 && !filepath.IsAbs(d.Command[0]) {
			return nil, errors.New("command executable must be absolute")
		}
		if d.CommandTimeout != "" {
			dur, e := time.ParseDuration(d.CommandTimeout)
			if e != nil || dur <= 0 {
				return nil, errors.New("invalid command timeout")
			}
		}
		if _, e = parseMode(d.Mode); e != nil {
			return nil, e
		}
		out[entry.Name()] = d
	}
	return out, nil
}

// Sync attempts every independent definition. A failure never removes the last
// deployed file or advances its successful revision. Each poll retries failures.
func (a *Agent) Sync(ctx context.Context) error {
	if e := a.Enroll(ctx); e != nil {
		return e
	}
	defs, e := a.definitions()
	if e != nil {
		return e
	}
	var failures []error
	for name, d := range defs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e = a.syncOne(ctx, name, d); e != nil {
			a.Log.Warn("secret synchronization failed", "definition", name, "error", e)
			failures = append(failures, fmt.Errorf("definition %s failed", name))
		}
	}
	return errors.Join(failures...)
}
func (a *Agent) syncOne(ctx context.Context, name string, d Definition) error {
	source := ""
	if d.Template != "" {
		p := filepath.Join(a.Config.TemplatesDir, d.Template)
		st, e := os.Lstat(p)
		if e != nil {
			return errors.New("template unavailable")
		}
		if !st.Mode().IsRegular() {
			return errors.New("template must be a regular file")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return errors.New("template unavailable")
		}
		source = string(b)
	}
	b, e := json.Marshal(d)
	if e != nil {
		return e
	}
	fingerprint := security.Hash(string(b) + "\x00" + source)
	path := d.Path
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	path = strings.Join(parts, "/")
	var meta struct {
		Revision int64 `json:"revision"`
	}
	if e = a.request(ctx, "metadata/"+path, "GET", nil, &meta); e != nil {
		return e
	}
	if meta.Revision < 1 {
		return errors.New("invalid server revision")
	}
	mode, e := parseMode(d.Mode)
	if e != nil {
		return e
	}
	uid, e := id(d.Owner, false)
	if e != nil {
		return e
	}
	gid, e := id(d.Group, true)
	if e != nil {
		return e
	}
	old := a.state[name]
	deployed := false
	st, e := os.Lstat(d.Destination)
	if e == nil && st.Mode().IsRegular() {
		current, e := os.ReadFile(d.Destination)
		deployed = e == nil && security.Hash(string(current)) == old.OutputHash && st.Mode().Perm() == mode
		if stat, ok := st.Sys().(*syscall.Stat_t); ok {
			deployed = deployed && (uid == -1 || int(stat.Uid) == uid) && (gid == -1 || int(stat.Gid) == gid)
		}
	}
	if old.Revision == meta.Revision && old.Fingerprint == fingerprint && deployed {
		if old.PendingCommand {
			return a.runCommand(ctx, name, d)
		}
		return nil
	}
	var value struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
		Revision int64 `json:"revision"`
	}
	if e = a.request(ctx, "secrets/"+path, "GET", nil, &value); e != nil {
		return e
	}
	if value.Revision < 1 {
		return errors.New("invalid value revision")
	}
	data := []byte(value.Data.Value)
	if d.Template != "" {
		data, e = Render(source, value.Data.Value, d.Path, value.Revision)
		if e != nil {
			return e
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = AtomicWrite(d.Destination, data, mode, uid, gid); e != nil {
		return errors.New("atomic destination write failed")
	}
	// Persist after publication, before the hook. A crash before this save causes
	// a safe repeat; a crash during a hook gives at-least-once hook execution.
	a.state[name] = Applied{value.Revision, fingerprint, security.Hash(string(data)), len(d.Command) > 0}
	if e = a.save(); e != nil {
		a.state[name] = old
		return errors.New("could not persist revision")
	}
	if len(d.Command) > 0 {
		return a.runCommand(ctx, name, d)
	}
	return nil
}
func (a *Agent) runCommand(ctx context.Context, name string, d Definition) error {
	if len(d.Command) == 0 {
		return nil
	}
	timeout := 30 * time.Second
	if d.CommandTimeout != "" {
		timeout, _ = time.ParseDuration(d.CommandTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.Command[0], d.Command[1:]...)
	// Cancel the entire local hook process group, including children of a shell.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	// Deliberately discard output: applications may echo secret contents. There is
	// no shell interpolation unless the local operator explicitly chooses a shell.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return errors.New("post-change command failed")
	}
	v := a.state[name]
	v.PendingCommand = false
	a.state[name] = v
	if e := a.save(); e != nil {
		v.PendingCommand = true
		a.state[name] = v
		return errors.New("could not persist command completion")
	}
	return nil
}
func (a *Agent) Run(ctx context.Context) error {
	defer a.Client.CloseIdleConnections()
	for {
		if e := a.Sync(ctx); e != nil && ctx.Err() == nil {
			a.Log.Warn("synchronization will retry", "error", e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(a.interval):
		}
	}
}
