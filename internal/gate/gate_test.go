package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhttp/internal/ca"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// fakeConsole serves the policy, as lockhttp's console does; the gate asks
// the hub (fakeHub) about held requests.
type fakeConsole struct {
	pol  *policy.Policy
	down atomic.Bool
}

func (f *fakeConsole) Policy(context.Context) (wire.PolicyResult, error) {
	if f.down.Load() {
		return wire.PolicyResult{}, ErrNoConsole
	}
	return wire.PolicyResult{Policy: *f.pol, Fingerprint: f.pol.Fingerprint()}, nil
}

const testPolicy = `
[profiles.default]
hold = "2s"
trusted = ["trusted.test", "api.anthropic.com"]
[[profiles.default.rules]]
id = "upload-free"
host = "big.test"
verdict = "free"
`

type env struct {
	t        *testing.T
	gate     *Gate
	console  *fakeConsole
	hub      *fakeHub
	callsMu  sync.Mutex
	calls    []wire.ApproveParams // what the gate asked the hub about
	addr     string
	backends map[string]string // host -> listener address
	roots    *x509.CertPool
	caPool   *x509.CertPool
	audit    *bytes.Buffer
	auditMu  *sync.Mutex
}

type lockedBuf struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// newEnv starts a gate in direct mode whose resolver maps every name to a
// public test address and whose dialer reaches the named test server. Its
// fake hub denies every ticket ("no") unless the test answers otherwise
// (e.hub.answerAll).
func newEnv(t *testing.T, conf string, mitm bool, mutate func(*Config)) *env {
	t.Helper()
	e := newEnvHub(t, conf, mitm, nil, nil, mutate)
	e.hub.answerAll(ticket.Denied, "no")
	return e
}

// newEnvHub is newEnv with its fake hub's client configuration changed by
// config and its Hub by hubMut, and a hub that answers nothing by itself.
func newEnvHub(t *testing.T, conf string, mitm bool, config func(*hubclient.Config), hubMut func(*Hub), mutate func(*Config)) *env {
	t.Helper()
	p, err := policy.Parse([]byte(conf), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeConsole{pol: &p}
	fh, h := newTestHub(t, config, hubMut)
	e := &env{t: t, console: fc, hub: fh, backends: map[string]string{}, audit: &bytes.Buffer{}, auditMu: &sync.Mutex{}}
	upstreamRoots := x509.NewCertPool()
	e.roots = upstreamRoots
	log, _ := NewAuditLog("", lockedBuf{e.auditMu, e.audit}, time.Now)
	cfg := Config{
		Profile: "default", Console: fc, Audit: log, PolicyPoll: 50 * time.Millisecond, Hub: h, Log: hubLog{t, fh},
		UpstreamTLS: &tls.Config{RootCAs: upstreamRoots},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "private.test" {
				return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		},
	}
	cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("no route to %s", addr)
	}
	if mitm {
		cp, kp, err := ca.Generate("test", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		authority, err := ca.Parse(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certs = localCerts{authority}
		e.caPool = x509.NewCertPool()
		e.caPool.AddCert(authority.Cert)
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e.gate = New(cfg)
	// Before the queue runs: record what the gate asks the hub about.
	approve := e.gate.queue.approve
	e.gate.queue.approve = func(ctx context.Context, fp string, p wire.ApproveParams) (wire.ApproveResult, error) {
		e.callsMu.Lock()
		e.calls = append(e.calls, p)
		e.callsMu.Unlock()
		return approve(ctx, fp, p)
	}
	g := e.gate
	// Runs after the cleanup below stopped the gate, before the hub and
	// the plans directory go: the stopped asks withdraw their tickets
	// first.
	t.Cleanup(func() {
		select {
		case <-g.Stopped():
		case <-time.After(10 * time.Second):
			t.Error("the gate did not stop")
		}
		// Before the plans directory goes (Windows refuses to remove a
		// locked file).
		if err := cfg.Hub.Close(); err != nil {
			t.Error(err)
		}
	})
	e.gate.cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// The resolver gave 203.0.113.10: reach the backend the test
		// registered for the port.
		_, port, _ := net.SplitHostPort(addr)
		for _, a := range e.backends {
			if strings.HasSuffix(a, ":"+port) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", a)
			}
		}
		return nil, fmt.Errorf("no backend for %s", addr)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	go e.gate.Run(ctx)
	go func() { _ = e.gate.Serve(ctx, ln) }()
	e.addr = ln.Addr().String()
	e.waitPolicy()
	return e
}

// Calls are the asks the gate sent to the hub, in order.
func (e *env) Calls() []wire.ApproveParams {
	e.callsMu.Lock()
	defer e.callsMu.Unlock()
	return append([]wire.ApproveParams(nil), e.calls...)
}

type localCerts struct{ c *ca.CA }

func (l localCerts) Certificate(_ context.Context, host string) (*tls.Certificate, error) {
	return l.c.Issue(host)
}

func (e *env) waitPolicy() {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := e.gate.Policy(); p != nil && e.gate.consoleUp.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatal("the gate never got the policy")
}

// backend starts a TLS (or plain) server for host on a port the gate's
// dialer maps.
func (e *env) backend(host string, tlsOn bool, h http.Handler) {
	var s *httptest.Server
	if tlsOn {
		s = httptest.NewUnstartedServer(h)
		s.StartTLS()
		e.roots.AddCert(s.Certificate())
	} else {
		s = httptest.NewServer(h)
	}
	e.t.Cleanup(s.Close)
	e.backends[host] = s.Listener.Addr().String()
}

func (e *env) port(host string) string {
	_, p, _ := net.SplitHostPort(e.backends[host])
	return p
}

// client returns an HTTP client through the gate. In connect mode the
// TLS target's certificate is httptest's (valid for example.com): the
// client checks it against that pool with the target name overridden.
func (e *env) client(user string, mitm bool) *http.Client {
	pu := &url.URL{Scheme: "http", Host: e.addr}
	if user != "" {
		pu.User = url.UserPassword(user, "tok-"+user)
	}
	tc := &tls.Config{RootCAs: e.roots}
	if mitm {
		tc = &tls.Config{RootCAs: e.caPool}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: tc, DisableKeepAlives: true}}
}

// auditText waits briefly for the audit to settle (tunnels are audited
// when they close, after the client saw its answer).
func (e *env) auditText() string {
	time.Sleep(100 * time.Millisecond)
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	return e.audit.String()
}

func ok(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	fmt.Fprintf(w, "ok %s %s %d", r.Method, r.URL.Path, len(b))
}

func TestConnectTrusted(t *testing.T) {
	e := newEnv(t, testPolicy, false, nil)
	e.backend("trusted.test", true, http.HandlerFunc(ok))
	c := e.client("dev-5", false)
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	resp, err := c.Get("https://trusted.test:" + e.port("trusted.test") + "/x")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("port other than 443 must hit the floor, got %s", resp.Status)
	}
	if !strings.Contains(e.auditText(), `"rule":"floor:port"`) {
		t.Fatalf("audit lacks the floor:\n%s", e.auditText())
	}
}

// remapPort makes 443/80 reach the test backends: the gate dials
// 203.0.113.10:443, the env dialer maps by port, so register the backend
// address under the standard port.
func (e *env) remap(host string, port string) {
	addr := e.backends[host]
	e.gate.cfg.Dial = func(ctx context.Context, network, a string) (net.Conn, error) {
		var d net.Dialer
		_, p, _ := net.SplitHostPort(a)
		if p == port {
			return d.DialContext(ctx, "tcp", addr)
		}
		return nil, fmt.Errorf("no backend for %s", a)
	}
	e.gate.transport.DialContext = e.gate.dialTarget
}

func TestConnectFreeAndAsk(t *testing.T) {
	e := newEnv(t, testPolicy, false, nil)
	e.backend("t", true, http.HandlerFunc(ok))
	e.remap("t", "443")
	c := e.client("dev-5", false)
	// The gate checks SNI against the CONNECT host; the test server's
	// certificate names example.com, so the client sends that SNI to a
	// CONNECT for example.com... which is unknown: ask.
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = ""
	resp, err := c.Get("https://trusted.test/x")
	if err == nil {
		resp.Body.Close()
	}
	// trusted.test FREE: the tunnel opens; the TLS check fails at the
	// client (the certificate names example.com), which proves the gate
	// let it through.
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("trusted CONNECT should reach the target: %v", err)
	}
	if !strings.Contains(e.auditText(), `"event":"free"`) || !strings.Contains(e.auditText(), `"host":"trusted.test"`) {
		t.Fatalf("audit:\n%s", e.auditText())
	}
	if len(e.Calls()) != 0 {
		t.Fatal("a trusted host asked the console")
	}

	// example.com is unknown: the console is asked; approved once, the
	// grant covers the next connection.
	e.hub.answerAll(ticket.Approved, "")
	resp, err = c.Get("https://example.com/x")
	if err != nil {
		t.Fatalf("approved CONNECT: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok GET /x 0" {
		t.Fatalf("body %q", b)
	}
	calls := e.Calls()
	if len(calls) != 1 || calls[0].Phase != "connect" || !calls[0].NeverAuto || calls[0].Agent != "dev-5" || calls[0].Grant != 600 {
		t.Fatalf("approve params: %+v", calls)
	}
	e.hub.answerAll(ticket.Denied, "no")
	resp, err = c.Get("https://example.com/y")
	if err != nil {
		t.Fatalf("connect grant not used: %v", err)
	}
	resp.Body.Close()
	if len(e.Calls()) != 1 {
		t.Fatal("the grant asked again")
	}
}

func TestConnectDenied(t *testing.T) {
	e := newEnv(t, testPolicy, false, nil)
	c := e.client("", false)
	_, err := c.Get("https://unknown.test/")
	if err == nil {
		t.Fatal("denied CONNECT passed")
	}
	if !strings.Contains(e.auditText(), `"code":"E_DENIED"`) {
		t.Fatalf("audit:\n%s", e.auditText())
	}
}

func TestNoConsole(t *testing.T) {
	e := newEnv(t, testPolicy, false, nil)
	e.console.down.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for e.gate.consoleUp.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	req, _ := http.NewRequest("GET", "http://unknown.test/x", nil)
	resp, err := e.client("", false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_NO_CONSOLE" || !strings.Contains(string(b), "lockhttp console") {
		t.Fatalf("no console: %s %v %s", resp.Status, resp.Header, b)
	}
	if time.Since(start) > time.Second {
		t.Fatal("E_NO_CONSOLE must be immediate")
	}
	// FREE continues on the cached policy.
	e.backend("trusted.test", false, http.HandlerFunc(ok))
	e.remap("trusted.test", "80")
	resp, err = e.client("", false).Get("http://trusted.test/x")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("FREE without console: %v %v", err, resp)
	}
	resp.Body.Close()
}

func TestPlainHTTPAndPrivate(t *testing.T) {
	e := newEnv(t, testPolicy, false, nil)
	e.backend("trusted.test", false, http.HandlerFunc(ok))
	e.remap("trusted.test", "80")
	resp, err := e.client("", false).Get("http://trusted.test/a")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok GET /a 0" || resp.Header.Get("X-LockHTTP-Request") == "" {
		t.Fatalf("plain: %q %v", b, resp.Header)
	}
	// A name resolving to a private address is refused after approval.
	e.hub.answerAll(ticket.Approved, "")
	resp, err = e.client("", false).Get("http://private.test/a")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("private target: %s", resp.Status)
	}
}

func TestMITM(t *testing.T) {
	e := newEnv(t, testPolicy, true, nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	// Upstream verification: the backend's cert names example.com, so
	// the targets here are example.com (trusted below via a rule-free
	// policy update).
	p, _ := policy.Parse([]byte(testPolicy+"\ntrusted = []\n"), "c", "default")
	_ = p
	c := e.client("dev-5", true)
	// GET to an unknown host asks; denied.
	resp, err := c.Get("https://example.com/r")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_DENIED" {
		t.Fatalf("unknown GET: %s %v", resp.Status, resp.Header)
	}
	calls := e.Calls()
	if len(calls) != 1 || calls[0].Phase != "http" || calls[0].TLS != "mitm" || calls[0].Path != "/r" {
		t.Fatalf("calls: %+v", calls)
	}
	// Approved POST goes through with its body.
	e.hub.answerAll(ticket.Approved, "")
	resp, err = c.Post("https://example.com/w", "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok POST /w 7" {
		t.Fatalf("approved POST: %s %q", resp.Status, b)
	}
	last := e.Calls()[len(e.Calls())-1]
	if !strings.Contains(last.Preview, `"a":1`) || last.BodyFP == "" || last.ReqBytes != 7 {
		t.Fatalf("POST params: %+v", last)
	}
	// A secret to another host is denied without asking.
	n := len(e.Calls())
	resp, err = c.Post("https://example.com/w", "text/plain", strings.NewReader("ghp_"+strings.Repeat("a1B2", 9)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" || len(e.Calls()) != n {
		t.Fatalf("secret: %s %v", resp.Status, resp.Header)
	}
}

func TestMITMClaudeAPI(t *testing.T) {
	e := newEnv(t, testPolicy, true, nil)
	e.backend("api.anthropic.com", true, http.HandlerFunc(ok))
	e.remap("api.anthropic.com", "443")
	// The httptest certificate names example.com, not api.anthropic.com:
	// the gate must refuse to talk to an upstream it cannot verify.
	c := e.client("dev-5", true)
	resp, err := c.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("an unverifiable upstream must fail: %s", resp.Status)
	}
	if !strings.Contains(e.auditText(), `"rule":"claude:messages"`) {
		t.Fatalf("audit:\n%s", e.auditText())
	}
	resp, err = c.Post("https://api.anthropic.com/v1/messages", "application/json",
		strings.NewReader(`{"mcp_servers":[{"type":"url","url":"https://mcp.example/sse","name":"x"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	calls := e.Calls()
	if resp.StatusCode != 403 || len(calls) != 1 || !calls[0].NeverAuto || !strings.Contains(strings.Join(calls[0].Warnings, " "), "mcp.example") {
		t.Fatalf("mcp_servers: %s %+v", resp.Status, calls)
	}
}

func TestIdenticalShareDistinctSeparate(t *testing.T) {
	e := newEnv(t, testPolicy, true, nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	var mu sync.Mutex
	e.hub.answerAll("", "") // the test decides
	c := e.client("dev-5", true)
	var wg sync.WaitGroup
	codes := map[int]int{}
	send := func(body string) {
		defer wg.Done()
		resp, err := c.Post("https://example.com/same", "application/json", strings.NewReader(body))
		if err != nil {
			t.Error(err)
			return
		}
		resp.Body.Close()
		mu.Lock()
		codes[resp.StatusCode]++
		mu.Unlock()
	}
	wg.Add(3)
	go send(`{"a":1}`)
	go send(`{"a":1}`)
	time.Sleep(200 * time.Millisecond)
	go send(`{"a":2}`)
	for _, tk := range e.hub.waitTickets(2) {
		e.hub.decide(tk, ticket.Approved, "", nil, "")
	}
	wg.Wait()
	calls := e.Calls()
	if len(calls) != 2 {
		t.Fatalf("want 2 items (identical shared, distinct separate), got %d", len(calls))
	}
	if codes[200] != 3 {
		t.Fatalf("codes %v", codes)
	}
	// The asks go to the hub at once: the second is sent while the first
	// still waits under the same key.
	if calls[0].Pending != 1 || calls[1].Pending != 2 {
		t.Fatalf("pending count: %+v %+v", calls[0].Pending, calls[1].Pending)
	}
}

func TestShadowMode(t *testing.T) {
	e := newEnv(t, strings.Replace(testPolicy, "[profiles.default]\n", "[profiles.default]\nmode = \"shadow\"\n", 1), false, nil)
	e.backend("unknown.test", false, http.HandlerFunc(ok))
	e.remap("unknown.test", "80")
	resp, err := e.client("", false).Post("http://unknown.test/x", "application/json", strings.NewReader("{}"))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("shadow: %v %v", err, resp)
	}
	resp.Body.Close()
	if !strings.Contains(e.auditText(), `"shadow":"ask"`) || len(e.Calls()) != 0 {
		t.Fatalf("shadow audit:\n%s", e.auditText())
	}
}

func TestSourcesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.json")
	write := func(v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tok := func(s string) string { return sum([]byte(s)) }
	write(map[string]any{"version": 1,
		"networks": []map[string]string{{"local_ip": "10.89.3.2", "container": "lea-a", "project": "shop"}},
		"keyproxy": map[string]string{"token_sha256": tok("kp")},
		"agents": []map[string]string{
			{"token_sha256": tok("t5"), "container": "lea-a", "agent": "dev-5", "role": "dev"},
			{"token_sha256": tok("tb"), "container": "lea-b", "agent": "dev-9"},
			{"token_sha256": tok("tn"), "container": "lea-a", "agent": "nested"},
		}})
	s := NewSources(path)
	ip := netip.MustParseAddr("10.89.3.2")
	if src, err := s.Resolve(ip, "dev-5", "t5", ""); err != nil || src.Container != "lea-a" || src.Agent != "dev-5" || src.Attribution != "proxy-auth" || src.Role != "dev" {
		t.Fatalf("agent: %+v %v", src, err)
	}
	if src, _ := s.Resolve(ip, "dev-9", "tb", ""); src.Container != "lea-a" || src.Attribution != "ambiguous" {
		t.Fatalf("token of another container: %+v", src)
	}
	if src, _ := s.Resolve(ip, "x", "nope", ""); src.Attribution != "unverified" {
		t.Fatalf("unknown token: %+v", src)
	}
	if src, _ := s.Resolve(ip, "nested", "tn", ""); src.Via != "nested" {
		t.Fatalf("nested: %+v", src)
	}
	if _, err := s.Resolve(netip.MustParseAddr("10.89.4.2"), "", "", ""); err == nil {
		t.Fatal("unknown network accepted")
	}
	lo := netip.MustParseAddr("127.0.0.1")
	if src, err := s.Resolve(lo, "keyproxy", "kp", "lea-a"); err != nil || src.Via != "keyproxy" || src.Container != "lea-a" {
		t.Fatalf("keyproxy: %+v %v", src, err)
	}
	if _, err := s.Resolve(lo, "keyproxy", "bad", "lea-a"); err == nil {
		t.Fatal("loopback without the keyproxy token accepted")
	}
	if _, err := s.Resolve(lo, "keyproxy", "kp", "lea-zz"); err == nil {
		t.Fatal("keyproxy for an unknown container accepted")
	}
	// A broken file fails closed.
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))
	s.Reload()
	if _, err := s.Resolve(ip, "dev-5", "t5", ""); err == nil {
		t.Fatal("broken sources file must fail closed")
	}
}

func TestSourceUnknownRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.json")
	_ = os.WriteFile(path, []byte(`{"version":1,"networks":[{"local_ip":"10.9.9.9","container":"lea-x"}]}`), 0o644)
	e := newEnv(t, testPolicy, false, func(c *Config) { c.Sources = NewSources(path) })
	resp, err := e.client("", false).Get("http://trusted.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-LockHTTP-Code") != "E_SOURCE_UNKNOWN" {
		t.Fatalf("got %s %v", resp.Status, resp.Header)
	}
}

func TestBodyHelpers(t *testing.T) {
	a := BodyFingerprint("multipart/form-data; boundary=AAA", []byte("--AAA\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nhello\r\n--AAA--\r\n"))
	b := BodyFingerprint("multipart/form-data; boundary=BBB", []byte("--BBB\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nhello\r\n--BBB--\r\n"))
	if a != b || !strings.HasPrefix(a, "mp:") {
		t.Fatalf("multipart boundary changes the fingerprint: %s %s", a, b)
	}
	if BodyFingerprint("application/json", []byte(`{"b":1,"a":2,"nonce":"x"}`)) != BodyFingerprint("application/json", []byte(`{"a":2,"b":1,"nonce":"y"}`)) {
		t.Fatal("json not canonical")
	}
	p := Preview("application/json", []byte(`{"mail":"jane.doe@example.com","k":"ghp_`+strings.Repeat("a", 36)+`"}`))
	if strings.Contains(p, "jane.doe@example.com") || strings.Contains(p, "ghp_") {
		t.Fatalf("preview not masked: %s", p)
	}
	if Preview("application/octet-stream", []byte{0, 1, 2}) != "(application/octet-stream, 3 bytes, not shown)" {
		t.Fatal("binary preview")
	}
	pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
	body := pkt(strings.Repeat("0", 40)+" "+strings.Repeat("a", 40)+" refs/heads/new\x00report-status") +
		pkt(strings.Repeat("b", 40)+" "+strings.Repeat("0", 40)+" refs/heads/old") + "0000PACK"
	refs := PushRefs([]byte(body))
	if len(refs) != 2 || !strings.HasPrefix(refs[0], "create refs/heads/new") || !strings.HasPrefix(refs[1], "DELETE refs/heads/old") {
		t.Fatalf("refs: %v", refs)
	}
	if _, ok := serverName([]byte{0x16, 3, 1, 0, 1, 1}); ok {
		t.Fatal("short hello parsed")
	}
	for _, c := range []struct {
		port            int
		internal        bool
		sni             string
		isTLS, complete bool
		refused         bool
	}{
		{443, false, "a.test", true, true, false},
		{443, false, "b.test", true, true, true},
		{443, false, "", true, true, true},
		{443, false, "a.test", true, false, true},
		{443, false, "", false, false, true},
		{80, false, "", false, false, false},
		{8080, true, "", false, false, false},
		{443, true, "", false, false, false},
	} {
		if got := helloRefusal("a.test", c.port, c.internal, c.sni, c.isTLS, c.complete) != ""; got != c.refused {
			t.Errorf("helloRefusal(%+v) refused=%v", c, got)
		}
	}
	if BodyFingerprint("application/json", []byte(`{"a":1,"x":{"b":1,"b":2}}`)) == BodyFingerprint("application/json", []byte(`{"a":1,"x":{"b":2}}`)) {
		t.Fatal("duplicate keys canonicalised")
	}
	if BodyFingerprint("application/json", []byte(`{"a":"\ud800"}`)) == BodyFingerprint("application/json", []byte(`{"a":"\ud801"}`)) {
		t.Fatal("lone surrogates merged")
	}
	if !strings.HasPrefix(BodyFingerprint("application/json", []byte(`{"a":[{"b":1},{"b":1}],"c":{"d":{"e":1}}}`)), "json:") {
		t.Fatal("same key in sibling objects is not a duplicate")
	}
	if BodyFingerprint("application/json", []byte(`{"a":1,"nonce":"x"} {"leak":1}`)) == BodyFingerprint("application/json", []byte(`{"a":1}`)) {
		t.Fatal("trailing JSON ignored")
	}
	if BodyFingerprint("application/json", []byte(`{"a":1,"nonce":{"leak":"data"}}`)) == BodyFingerprint("application/json", []byte(`{"a":1}`)) {
		t.Fatal("a structured volatile field is dropped")
	}
	pre := BodyFingerprint("multipart/form-data; boundary=AAA", []byte("LEAK\r\n--AAA\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nhello\r\n--AAA--\r\n"))
	if pre == a {
		t.Fatal("multipart preamble ignored")
	}
}
