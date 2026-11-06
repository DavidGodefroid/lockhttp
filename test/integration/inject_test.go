//go:build integration && linux

package integration

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/gate"
)

const injectSecret = "ha-integration-0123456789"

const injectPolicyText = `
[profiles.default]
hold = "5s"
trusted = ["trusted.test"]

[[profiles.default.internal_hosts]]
host  = "homeassistant"
ports = [8123]
read  = true

[[profiles.default.inject]]
id         = "ha"
host       = "homeassistant"
port       = 8123
header     = "Authorization"
scheme     = "Bearer"
credential = "ha-token"
`

// authBackend records the Authorization each request carried and answers
// whether it was the expected one, never the value.
type authBackend struct {
	mu   sync.Mutex
	auth []string
}

func (a *authBackend) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.auth = append(a.auth, r.Header.Get("Authorization"))
		a.mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer "+injectSecret {
			_, _ = io.WriteString(w, "authenticated "+r.Host+r.URL.Path)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func (a *authBackend) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auth...)
}

// The agent calls an authenticated internal API without holding its
// token: the console approves a policy that names the secret only, the
// gate adds the header from its own secrets file, and a request carrying
// the value is refused.
func TestCredentialInjection(t *testing.T) {
	setRuntime(t)
	h := &human{answers: make(chan string, 8)}
	stop := startConsoleWith(t, h, injectPolicyText)
	defer stop()
	// The human approved a policy that shows the injection, by name.
	if txt := h.text(); !strings.Contains(txt, "inject ha homeassistant:8123 Authorization Bearer credential=ha-token") || strings.Contains(txt, injectSecret) {
		t.Fatalf("the console's description:\n%s", txt)
	}
	secrets := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(secrets, []byte(`{"version":1,"secrets":{"ha-token":"`+injectSecret+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	auditDir := filepath.Join(t.TempDir(), "audit")
	var be authBackend
	addr, _, hub := startGateWith(t, be.start(t), func(c *gate.Config) {
		c.Secrets = gate.NewSecrets(secrets)
		log, err := gate.NewAuditLog(auditDir, nil, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		c.Audit = log
	})
	c := client(addr)

	// No credential from the agent: the gate adds it, the API answers.
	resp, body := get(t, c, "GET", "http://homeassistant:8123/api/states", "")
	if resp.StatusCode != 200 || body != "authenticated homeassistant:8123/api/states" {
		t.Fatalf("injected call: %s %q", resp.Status, body)
	}
	if n := len(hub.Tickets()); n != 0 {
		t.Fatalf("an internal read asked the hub (%d tickets)", n)
	}
	// The agent's own Authorization never reaches the API.
	req, _ := http.NewRequest("GET", "http://homeassistant:8123/api/config", nil)
	req.Header.Set("Authorization", "Bearer guessed-by-the-agent")
	r2, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("replaced credential: %s", r2.Status)
	}
	for _, a := range be.seen() {
		if a != "Bearer "+injectSecret {
			t.Fatalf("the API saw Authorization %q", a)
		}
	}
	// The value, sent by the agent to any host, is refused.
	resp, _ = get(t, c, "GET", "http://trusted.test/x?t="+url.QueryEscape(injectSecret), "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("leak: %s %v", resp.Status, resp.Header)
	}
	if n := len(be.seen()); n != 2 {
		t.Fatalf("the backend saw %d requests, want 2", n)
	}
	// The audit names the injection, never the value.
	time.Sleep(100 * time.Millisecond)
	files, _ := filepath.Glob(filepath.Join(auditDir, "gate-*.jsonl"))
	var audit strings.Builder
	for _, f := range files {
		b, _ := os.ReadFile(f)
		audit.Write(b)
	}
	a := audit.String()
	if !strings.Contains(a, `"injected":["ha:Authorization"]`) || !strings.Contains(a, `"rule":"secret:injected"`) {
		t.Fatalf("audit:\n%s", a)
	}
	if strings.Contains(a, injectSecret) || strings.Contains(a, "guessed-by-the-agent") {
		t.Fatalf("the audit holds a credential value:\n%s", a)
	}
}

// An API that reflects the credential the gate added hands the agent
// none of it: the gate redacts it from the response, refuses TRACE to
// the host, and refuses the value the agent sends back, even in base64.
func TestCredentialInjectionReflection(t *testing.T) {
	setRuntime(t)
	h := &human{answers: make(chan string, 8)}
	stop := startConsoleWith(t, h, injectPolicyText)
	defer stop()
	secrets := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(secrets, []byte(`{"version":1,"secrets":{"ha-token":"`+injectSecret+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var traced bool
	var mu sync.Mutex
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" {
			mu.Lock()
			traced = true
			mu.Unlock()
		}
		a := r.Header.Get("Authorization")
		w.Header().Set("X-Echo", a)
		_, _ = io.WriteString(w, "you sent "+a+" b64 "+base64.StdEncoding.EncodeToString([]byte(a)))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	addr, _, _ := startGateWith(t, ln.Addr().String(), func(c *gate.Config) { c.Secrets = gate.NewSecrets(secrets) })
	c := client(addr)

	resp, body := get(t, c, "GET", "http://homeassistant:8123/api/echo", "")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "you sent Bearer ****") {
		t.Fatalf("echo: %s %q", resp.Status, body)
	}
	if strings.Contains(body, injectSecret) || strings.Contains(resp.Header.Get("X-Echo"), injectSecret) ||
		strings.Contains(body, base64.StdEncoding.EncodeToString([]byte(injectSecret))[4:20]) {
		t.Fatalf("the agent got the credential: %v %q", resp.Header, body)
	}
	resp, _ = get(t, c, "TRACE", "http://homeassistant:8123/api/echo", "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_METHOD" {
		t.Fatalf("TRACE: %s %v", resp.Status, resp.Header)
	}
	mu.Lock()
	defer mu.Unlock()
	if traced {
		t.Fatal("TRACE reached the API")
	}
	resp, _ = get(t, c, "GET", "http://trusted.test/x?h="+hex.EncodeToString([]byte(injectSecret)), "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("hex leak: %s %v", resp.Status, resp.Header)
	}
}

// An injection limited to /api/*: the credential the API stores there is
// redacted from the other paths of the host, two ranges do not join it
// back, and a value in the host or a header name is refused before the
// gate resolves or audits it.
func TestCredentialInjectionWholeHost(t *testing.T) {
	setRuntime(t)
	conf := strings.Replace(injectPolicyText, `credential = "ha-token"`, `credential = "ha-token"
paths      = ["/api/*"]`, 1)
	h := &human{answers: make(chan string, 8)}
	stop := startConsoleWith(t, h, conf)
	defer stop()
	secrets := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(secrets, []byte(`{"version":1,"secrets":{"ha-token":"`+injectSecret+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var stored string
	var ranged, names bool
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Range") != "" || r.Header.Get("If-Range") != "" {
			ranged = true
		}
		for k := range r.Header {
			names = names || strings.Contains(strings.ToLower(k), injectSecret)
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			stored = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, "stored")
			return
		}
		http.ServeContent(w, r, "log", time.Time{}, strings.NewReader("log: "+stored+" end"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	auditDir := filepath.Join(t.TempDir(), "audit")
	addr, _, _ := startGateWith(t, ln.Addr().String(), func(c *gate.Config) {
		c.Secrets = gate.NewSecrets(secrets)
		log, err := gate.NewAuditLog(auditDir, nil, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		c.Audit = log
	})
	c := client(addr)
	if resp, body := get(t, c, "GET", "http://homeassistant:8123/api/states", ""); resp.StatusCode != 200 || body != "stored" {
		t.Fatalf("store: %s %q", resp.Status, body)
	}
	resp, body := get(t, c, "GET", "http://homeassistant:8123/log", "")
	if resp.StatusCode != 200 || strings.Contains(body, injectSecret) || !strings.HasPrefix(body, "log: Bearer ****") {
		t.Fatalf("/log: %s %q", resp.Status, body)
	}
	var joined string
	for _, rg := range []string{"bytes=0-23", "bytes=24-"} {
		req, _ := http.NewRequest("GET", "http://homeassistant:8123/log", nil)
		req.Header.Set("Range", rg)
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		joined += string(b)
	}
	if strings.Contains(joined, injectSecret) || strings.Contains(joined, injectSecret[:10]) {
		t.Fatalf("the ranges gave the secret: %q", joined)
	}
	resp, _ = get(t, c, "GET", "http://"+injectSecret+".example.com/", "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("host: %s %v", resp.Status, resp.Header)
	}
	req, _ := http.NewRequest("GET", "http://homeassistant:8123/log", nil)
	req.Header.Set("X-"+injectSecret, "1")
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 403 || r.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("header name: %s %v", r.Status, r.Header)
	}
	mu.Lock()
	if ranged || names {
		t.Fatalf("the API got a Range (%v) or the header name (%v)", ranged, names)
	}
	mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	files, _ := filepath.Glob(filepath.Join(auditDir, "gate-*.jsonl"))
	var audit strings.Builder
	for _, f := range files {
		b, _ := os.ReadFile(f)
		audit.Write(b)
	}
	if a := strings.ToLower(audit.String()); strings.Contains(a, injectSecret) || strings.Count(a, `"rule":"secret:injected"`) != 2 {
		t.Fatalf("audit:\n%s", audit.String())
	}
}

// An injection limited to /api/* never lends its credential to a path a
// target resolves outside it ("/api/../admin", encoded dots, an encoded
// slash), and TRACE or TRACK in any case of the method never reaches the
// API: the real target would echo the header.
func TestCredentialInjectionAmbiguousPathAndTraceCase(t *testing.T) {
	setRuntime(t)
	conf := strings.Replace(injectPolicyText, `credential = "ha-token"`, `credential = "ha-token"
paths      = ["/api/*"]`, 1)
	h := &human{answers: make(chan string, 8)}
	stop := startConsoleWith(t, h, conf)
	defer stop()
	secrets := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(secrets, []byte(`{"version":1,"secrets":{"ha-token":"`+injectSecret+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]string{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.Method+" "+r.RequestURI] = r.Header.Get("Authorization")
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+injectSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "authenticated")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	addr, _, _ := startGateWith(t, ln.Addr().String(), func(c *gate.Config) { c.Secrets = gate.NewSecrets(secrets) })
	c := client(addr)
	if resp, body := get(t, c, "GET", "http://homeassistant:8123/api/states", ""); resp.StatusCode != 200 || body != "authenticated" {
		t.Fatalf("/api/states: %s %q", resp.Status, body)
	}
	for _, p := range []string{"/api/../admin", "/api/%2e%2e/admin", "/api/%2E%2E%2Fadmin"} {
		resp, _ := get(t, c, "GET", "http://homeassistant:8123"+p, "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: %s (the API authenticated it)", p, resp.Status)
		}
		mu.Lock()
		a, ok := got["GET "+p]
		mu.Unlock()
		if !ok || a != "" {
			t.Fatalf("%s: reached %v, with the credential %v", p, ok, a != "")
		}
	}
	for _, m := range []string{"trace", "Trace", "track"} {
		resp, _ := get(t, c, m, "http://homeassistant:8123/api/echo", "")
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_METHOD" {
			t.Fatalf("%s: %s %v", m, resp.Status, resp.Header)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for k := range got {
		if strings.HasPrefix(strings.ToUpper(k), "TRACE") || strings.HasPrefix(strings.ToUpper(k), "TRACK") {
			t.Fatalf("%s reached the API", k)
		}
	}
}
