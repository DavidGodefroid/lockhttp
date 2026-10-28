//go:build integration && linux

// Package integration runs the gate against a real lockkit console in the
// same process: the console's same-user mode, which only a test build may
// turn on (lockkit IsolationEnv.AllowSameUser), on a private socket.
package integration

import (
	"context"
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

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/sysconf"

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

[[profiles.default.rules]]
id = "hooks"
host = "hooks.test"
methods = ["POST"]
verdict = "auto"
`

func startConsole(t *testing.T, h *human, auto bool) context.CancelFunc {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- console.Run(ctx, product.P, httpconsole.New(httpconsole.Options{Profile: "default", Config: cfg}), console.Options{
			Profile: "default", IO: h, StateDir: filepath.Join(dir, "state"), Auto: auto, Quantum: -1,
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

func startGate(t *testing.T, backend string) (string, *gate.Gate) {
	t.Helper()
	g := gate.New(gate.Config{
		Profile: "default", Console: &gate.LockkitConsole{Profile: "default"}, PolicyPoll: 100 * time.Millisecond,
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
	t.Cleanup(func() { cancel(); ln.Close() })
	go g.Run(ctx)
	go func() { _ = g.Serve(ctx, ln) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := g.Policy(); p != nil {
			return ln.Addr().String(), g
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the gate never received the console's policy")
	return "", nil
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
	stop := startConsole(t, h, false)
	defer stop()
	addr, _ := startGate(t, backend(t))
	c := client(addr)

	// Trusted read: free, the console is not asked.
	if resp, body := get(t, c, "GET", "http://trusted.test/a", ""); resp.StatusCode != 200 || body != "ok GET trusted.test/a " {
		t.Fatalf("trusted: %s %q", resp.Status, body)
	}
	// A write asks the human; y approves it.
	h.answers <- "y"
	if resp, body := get(t, c, "POST", "http://unknown.test/w", `{"a":1}`); resp.StatusCode != 200 || !strings.Contains(body, `{"a":1}`) {
		t.Fatalf("approved write: %s %q\n%s", resp.Status, body, h.text())
	}
	screen := h.text()
	for _, want := range []string{"POST unknown.test", "container local", "agent dev-5 (declared", "preview (masked)"} {
		if !strings.Contains(screen, want) {
			t.Fatalf("screen lacks %q:\n%s", want, screen)
		}
	}
	// n <reason> denies, and the reason reaches the agent.
	h.answers <- "n not now"
	resp, body := get(t, c, "POST", "http://unknown.test/w", `{"a":2}`)
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_DENIED" || !strings.Contains(body, "not now") {
		t.Fatalf("denied write: %s %v %q", resp.Status, resp.Header, body)
	}
}

func TestAutoModeOnlyForAutoRules(t *testing.T) {
	setRuntime(t)
	h := &human{answers: make(chan string, 8)}
	stop := startConsole(t, h, true)
	defer stop()
	addr, _ := startGate(t, backend(t))
	c := client(addr)
	// A rule with verdict auto: auto mode approves it without a prompt.
	if resp, _ := get(t, c, "POST", "http://hooks.test/x", `{}`); resp.StatusCode != 200 {
		t.Fatalf("auto rule: %s\n%s", resp.Status, h.text())
	}
	if !strings.Contains(h.text(), "auto-approved") {
		t.Fatalf("not auto-approved:\n%s", h.text())
	}
	// Any other write is NeverAuto: the human is asked even in auto mode.
	h.answers <- "n"
	if resp, _ := get(t, c, "POST", "http://other.test/x", `{}`); resp.StatusCode != 403 {
		t.Fatalf("NeverAuto write passed in auto mode: %s", resp.Status)
	}
}

func TestNoConsoleFailsClosed(t *testing.T) {
	setRuntime(t)
	h := &human{answers: make(chan string, 8)}
	stop := startConsole(t, h, false)
	addr, g := startGate(t, backend(t))
	stop()
	deadline := time.Now().Add(5 * time.Second)
	c := client(addr)
	for time.Now().Before(deadline) {
		resp, _ := get(t, c, "POST", "http://unknown.test/w", `{}`)
		if resp.Header.Get("X-LockHTTP-Code") == "E_NO_CONSOLE" {
			// Trusted reads go on with the cached policy.
			if resp, _ := get(t, c, "GET", "http://trusted.test/a", ""); resp.StatusCode != 200 {
				t.Fatalf("FREE without console: %s", resp.Status)
			}
			_ = g
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no E_NO_CONSOLE after the console stopped")
}
