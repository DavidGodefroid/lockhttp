package gate

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
)

const (
	haSecret  = "ha-long-lived-0123456789"
	apiSecret = "api-key-abcdefghijklmnop"
)

const injectPolicy = `
[profiles.default]
hold = "2s"
trusted = ["trusted.test", "example.com", "public.test"]

[[profiles.default.internal_hosts]]
host  = "homeassistant"
ports = [8123]
read  = true

[[profiles.default.internal_hosts]]
host  = "nas"
ports = [8080]
read  = true

[[profiles.default.inject]]
id         = "ha"
host       = "homeassistant"
port       = 8123
header     = "Authorization"
scheme     = "Bearer"
credential = "ha-token"

[[profiles.default.inject]]
id         = "api"
host       = "example.com"
port       = 443
header     = "X-Api-Key"
credential = "api-key"

[[profiles.default.inject]]
id         = "public"
host       = "public.test"
port       = 80
header     = "Authorization"
credential = "ha-token"

[[profiles.default.inject]]
id         = "gone"
host       = "nas"
port       = 8080
header     = "X-Api-Key"
credential = "missing"
`

func writeSecrets(t *testing.T, vals map[string]string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"version": 1, "secrets": vals})
	p := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// seen records the headers the backend received.
type seen struct {
	mu sync.Mutex
	h  []http.Header
}

func (s *seen) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.h = append(s.h, r.Header.Clone())
	s.mu.Unlock()
	_, _ = io.WriteString(w, "ok")
}

func (s *seen) last() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.h) == 0 {
		return nil
	}
	return s.h[len(s.h)-1]
}

func injectEnv(t *testing.T, mitm bool) *env {
	path := writeSecrets(t, map[string]string{"ha-token": haSecret, "api-key": apiSecret})
	return newEnv(t, injectPolicy, mitm, func(c *Config) { c.Secrets = NewSecrets(path) })
}

func do(t *testing.T, c *http.Client, method, u string, h http.Header, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	for k, vs := range h {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp
}

func TestInjectPlainInternal(t *testing.T) {
	e := injectEnv(t, false)
	var s seen
	e.backend("homeassistant", false, http.HandlerFunc(s.handler))
	e.remap("homeassistant", "8123")
	c := e.client("dev-5", false)
	// The agent sends no credential: the gate adds it.
	if resp := do(t, c, "GET", "http://homeassistant:8123/api/states", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("status %s", resp.Status)
	}
	if got := s.last().Get("Authorization"); got != "Bearer "+haSecret {
		t.Fatalf("backend got Authorization %q", got)
	}
	// An Authorization of the agent's own is replaced, never forwarded.
	resp := do(t, c, "GET", "http://homeassistant:8123/api/states", http.Header{"Authorization": {"Bearer agent-made"}}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %s", resp.Status)
	}
	if got := s.last().Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+haSecret {
		t.Fatalf("backend got %q", got)
	}
	a := e.auditText()
	if !strings.Contains(a, `"injected":["ha:Authorization"]`) || !strings.Contains(a, "replaced the agent's Authorization header") {
		t.Fatalf("audit:\n%s", a)
	}
	if strings.Contains(a, haSecret) {
		t.Fatal("the audit holds the secret's value")
	}
}

func TestInjectLeakRefused(t *testing.T) {
	e := injectEnv(t, false)
	var s seen
	e.backend("trusted.test", false, http.HandlerFunc(s.handler))
	e.remap("trusted.test", "80")
	c := e.client("dev-5", false)
	for name, send := range map[string]func() *http.Response{
		"query": func() *http.Response {
			return do(t, c, "GET", "http://trusted.test/x?k="+url.QueryEscape(haSecret), nil, "")
		},
		"path": func() *http.Response { return do(t, c, "GET", "http://trusted.test/"+haSecret, nil, "") },
		"header": func() *http.Response {
			return do(t, c, "GET", "http://trusted.test/x", http.Header{"X-Note": {"v=" + apiSecret}}, "")
		},
		"base64 header": func() *http.Response {
			return do(t, c, "GET", "http://trusted.test/x", http.Header{"X-Note": {base64.StdEncoding.EncodeToString([]byte(haSecret))}}, "")
		},
		"body": func() *http.Response {
			return do(t, c, "POST", "http://trusted.test/x", http.Header{"Content-Type": {"text/plain"}}, "token "+apiSecret)
		},
	} {
		resp := send()
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
			t.Errorf("%s: %s %v", name, resp.Status, resp.Header)
		}
	}
	if s.last() != nil {
		t.Fatal("a request carrying an injected secret reached the backend")
	}
	if len(e.Calls()) != 0 {
		t.Fatal("a leak asked the hub")
	}
	// The audit never holds the value, not even in a path.
	if a := e.auditText(); !strings.Contains(a, `"rule":"secret:injected"`) || strings.Contains(a, haSecret) || strings.Contains(a, apiSecret) {
		t.Fatalf("audit:\n%s", a)
	}
}

func TestInjectNotOnPlainPublic(t *testing.T) {
	e := injectEnv(t, false)
	var s seen
	e.backend("public.test", false, http.HandlerFunc(s.handler))
	e.remap("public.test", "80")
	if resp := do(t, e.client("dev-5", false), "GET", "http://public.test/x", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("status %s", resp.Status)
	}
	if got := s.last().Get("Authorization"); got != "" {
		t.Fatalf("a secret went in clear text to a public host: %q", got)
	}
	if a := e.auditText(); !strings.Contains(a, "inject public skipped") {
		t.Fatalf("audit:\n%s", a)
	}
}

func TestInjectMissingSecretFailsClosed(t *testing.T) {
	e := injectEnv(t, false)
	var s seen
	e.backend("nas", false, http.HandlerFunc(s.handler))
	e.remap("nas", "8080")
	resp := do(t, e.client("dev-5", false), "GET", "http://nas:8080/x", nil, "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_INJECT" {
		t.Fatalf("missing secret: %s %v", resp.Status, resp.Header)
	}
	if s.last() != nil {
		t.Fatal("the request went out without its credential")
	}
}

func TestInjectMITM(t *testing.T) {
	e := injectEnv(t, true)
	var s seen
	e.backend("example.com", true, http.HandlerFunc(s.handler))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	if resp := do(t, c, "GET", "https://example.com/r", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("status %s", resp.Status)
	}
	if got := s.last().Get("X-Api-Key"); got != apiSecret {
		t.Fatalf("backend got X-Api-Key %q", got)
	}
	// A write asks the hub: the screen says the gate adds the header,
	// without its value; approved, it goes out with it.
	e.hub.answerAll(ticket.Approved, "")
	if resp := do(t, c, "POST", "https://example.com/w", http.Header{"Content-Type": {"application/json"}}, `{"a":1}`); resp.StatusCode != 200 {
		t.Fatalf("approved POST: %s", resp.Status)
	}
	calls := e.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls: %+v", calls)
	}
	b, _ := json.Marshal(calls[0])
	if !strings.Contains(string(b), "the gate adds X-Api-Key (secret api-key, inject api)") || strings.Contains(string(b), apiSecret) {
		t.Fatalf("screen: %s", b)
	}
	if got := s.last().Get("X-Api-Key"); got != apiSecret {
		t.Fatalf("approved POST lacks the credential: %q", got)
	}
	if strings.Contains(e.auditText(), apiSecret) {
		t.Fatal("the audit holds the secret's value")
	}
}
