//go:build integration && linux

// Package integration runs the gate against a real lockkit console in the
// same process (the console's same-user mode, which only a test build may
// turn on: lockkit IsolationEnv.AllowSameUser, on a private socket) and
// lockkit's test hub: the console serves the policy, the hub decides the
// held requests.
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhttp/internal/gate"
	"github.com/DavidGodefroid/lockhttp/internal/httpconsole"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// human is the console's terminal: it answers prompts with what the test
// queued, and records every line.
type human struct {
	mu      sync.Mutex
	lines   []string
	answers chan string
}

func (h *human) Println(s string) { h.mu.Lock(); h.lines = append(h.lines, s); h.mu.Unlock() }

func (h *human) Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool) {
	h.Println("PROMPT " + prompt)
	select {
	case a := <-h.answers:
		return a, true
	case <-ctx.Done():
		return "", false
	case <-time.After(timeout):
		return "", false
	}
}

func (h *human) AskSecret(context.Context, string) ([]byte, error) { return nil, io.EOF }

func (h *human) text() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.lines, "\n")
}

const policyText = `
[profiles.default]
hold = "5s"
trusted = ["trusted.test"]
`

func startConsole(t *testing.T, h *human) context.CancelFunc {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	hubOpts := consoleHub(t)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- console.Run(ctx, product.P, httpconsole.New(httpconsole.Options{Profile: "default", Config: cfg}), console.Options{
			Profile: "default", IO: h, StateDir: filepath.Join(dir, "state"), Quantum: -1, Hub: hubOpts,
			Harden: func() error { return nil },
			Isolation: &console.IsolationEnv{
				AllowSameUser: true,
				LoadSys:       func() (*sysconf.Config, error) { return nil, nil },
				Display:       func() sysconf.Display { return sysconf.Display{} },
				UID:           os.Getuid,
			},
			Ready: func(s string) { ready <- s },
		})
	}()
	// First start: the console describes the policy and asks to approve it.
	h.answers <- "y"
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("console stopped: %v\n%s", err, h.text())
	case <-time.After(10 * time.Second):
		t.Fatalf("console not ready:\n%s", h.text())
	}
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the console did not stop")
		}
	}
}

// consoleHub is the console's own test hub (the console is hub-attached
// only): apart from the gate's, so that its decisions poll never takes one
// meant for the gate.
func consoleHub(t *testing.T) console.HubOptions {
	t.Helper()
	home := t.TempDir()
	key, err := hubclient.InstanceKey(home, "egress-console")
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, "egress-console", key.Public().(ed25519.PublicKey))
	keyFile := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return console.HubOptions{URL: hub.URL(), KeyFile: keyFile, Instance: "egress-console", Home: home}
}

// startGate starts a gate on the console's policy, asking a test hub.
func startGate(t *testing.T, backend string) (string, string, *hubtest.Hub) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, "egress", pub)
	// hubtest answers the decisions poll at once: slow it down, as a long
	// poll would, so that the client's watch does not spin.
	target, _ := url.Parse(hub.URL())
	rp := httputil.NewSingleHostReverseProxy(target)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/decisions" {
			time.Sleep(20 * time.Millisecond)
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(slow.Close)
	dir := t.TempDir()
	st, err := plans.Open(filepath.Join(dir, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := hubclient.New(hubclient.Config{URL: slow.URL, Instance: "egress", Key: key, HubKey: hub.Pub, StateFile: filepath.Join(dir, "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	h := &gate.Hub{Client: cl, Plans: st, Poll: 20 * time.Millisecond}
	g := gate.New(gate.Config{
		Profile: "default", Console: &gate.LockkitConsole{Profile: "default"}, PolicyPoll: 100 * time.Millisecond,
		Hub: h, StatusFile: filepath.Join(dir, "status.json"),
		Upstream: nil,
		Resolve:  func(context.Context, string) ([]netipAddr, error) { return []netipAddr{publicTestAddr}, nil },
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, backend)
		},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case <-g.Stopped():
		case <-time.After(10 * time.Second):
			t.Error("the gate did not stop")
		}
		_ = h.Close()
	})
	go g.Run(ctx)
	go func() { _ = g.Serve(ctx, ln) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := g.Policy(); p != nil {
			return ln.Addr().String(), filepath.Join(dir, "status.json"), hub
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the gate never received the console's policy")
	return "", "", nil
}

// decideNext decides the next ticket the hub gets (none of seen) o.
func decideNext(t *testing.T, hub *hubtest.Hub, seen map[string]bool, o ticket.Outcome, reason string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, id := range hub.Tickets() {
			if !seen[id] {
				seen[id] = true
				hub.Decide(id, o, reason)
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("no new ticket on the hub")
}

func client(addr string) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr, User: url.UserPassword("dev-5", "t")}), DisableKeepAlives: true}}
}

func backend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "ok "+r.Method+" "+r.Host+r.URL.Path+" "+string(b))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func setRuntime(t *testing.T) {
	// The console's private socket dir, short enough for a Unix socket.
	dir, err := os.MkdirTemp("/tmp", "lh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("LOCKHTTP_RUNTIME_DIR", dir)
}

func get(t *testing.T, c *http.Client, method, u, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestGateWithRealConsole(t *testing.T) {
	setRuntime(t)
	h := &human{answers: make(chan string, 8)}
	stop := startConsole(t, h)
	defer stop()
	addr, _, hub := startGate(t, backend(t))
	c := client(addr)
	prompts := strings.Count(h.text(), "PROMPT")

	// Trusted read: free, the hub is not asked.
	if resp, body := get(t, c, "GET", "http://trusted.test/a", ""); resp.StatusCode != 200 || body != "ok GET trusted.test/a " {
		t.Fatalf("trusted: %s %q", resp.Status, body)
	}
	if n := len(hub.Tickets()); n != 0 {
		t.Fatalf("a trusted read made %d tickets", n)
	}
	// A write is a ticket on the hub; approved there, it goes through.
	seen := map[string]bool{}
	go decideNext(t, hub, seen, ticket.Approved, "")
	if resp, body := get(t, c, "POST", "http://unknown.test/w", `{"a":1}`); resp.StatusCode != 200 || !strings.Contains(body, `{"a":1}`) {
		t.Fatalf("approved write: %s %q", resp.Status, body)
	}
	ids := hub.Tickets()
	if len(ids) != 1 {
		t.Fatalf("tickets %v", ids)
	}
	tk := string(hub.Ticket(ids[0]))
	for _, want := range []string{"unknown.test", "dev-5"} {
		if !strings.Contains(tk, want) {
			t.Fatalf("ticket lacks %q:\n%s", want, tk)
		}
	}
	// Denied on the hub, with the reason the agent gets.
	time.Sleep(50 * time.Millisecond)
	go decideNext(t, hub, seen, ticket.Denied, "not now")
	resp, body := get(t, c, "POST", "http://unknown.test/w", `{"a":2}`)
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_DENIED" || !strings.Contains(body, "not now") {
		t.Fatalf("denied write: %s %v %q", resp.Status, resp.Header, body)
	}
	// The console's terminal never asked about a request.
	if n := strings.Count(h.text(), "PROMPT"); n != prompts {
		t.Fatalf("the console asked its human about a request:\n%s", h.text())
	}
}

func TestNoConsoleFailsClosed(t *testing.T) {
	setRuntime(t)
	h := &human{answers: make(chan string, 8)}
	stop := startConsole(t, h)
	addr, status, _ := startGate(t, backend(t))
	stop()
	// The gate sees the console leave (its status file says down); its
	// next ask is refused at once.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(status); strings.Contains(string(b), `"console":"down"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	deadline = time.Now().Add(5 * time.Second)
	c := client(addr)
	for time.Now().Before(deadline) {
		resp, _ := get(t, c, "POST", "http://unknown.test/w", `{}`)
		if resp.Header.Get("X-LockHTTP-Code") == "E_NO_CONSOLE" {
			// Trusted reads go on with the cached policy.
			if resp, _ := get(t, c, "GET", "http://trusted.test/a", ""); resp.StatusCode != 200 {
				t.Fatalf("FREE without console: %s", resp.Status)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no E_NO_CONSOLE after the console stopped")
}
