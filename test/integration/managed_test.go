//go:build integration && linux && lockfamily_managed_test

package integration

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/lockhttp/internal/httpconsole"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

const managedBounds = `version = 1
organisation = "Example Corp"

[lockhttp.bounds]
mode = "enforce"
connect_grant = "10m"

[[lockhttp.bounds.rules]]
id = "no-tools"
host = "tools.test"
verdict = "deny"
`

// placeManaged makes the console and the gate's console read text as the
// company's managed file (test builds only); it returns its path.
func placeManaged(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
	return path
}

// managedConsole is a console started with console.Run on conf.
type managedConsole struct {
	cfg, state string
	done       chan error
	ready      chan string
	cancel     context.CancelFunc
}

func runManagedConsole(t *testing.T, h *human, conf string) *managedConsole {
	t.Helper()
	dir := t.TempDir()
	c := &managedConsole{cfg: filepath.Join(dir, "config.toml"), state: filepath.Join(dir, "state"),
		done: make(chan error, 1), ready: make(chan string, 1)}
	if err := os.WriteFile(c.cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go func() {
		c.done <- console.Run(ctx, product.P, httpconsole.New(httpconsole.Options{Profile: "default", Config: c.cfg}), console.Options{
			Profile: "default", IO: h, StateDir: c.state, Quantum: -1, PolicyOnly: true,
			Harden: func() error { return nil },
			Isolation: &console.IsolationEnv{
				AllowSameUser: true,
				LoadSys:       func() (*sysconf.Config, error) { return nil, nil },
				Display:       func() sysconf.Display { return sysconf.Display{} },
				UID:           os.Getuid,
			},
			Ready: func(s string) { c.ready <- s },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Error("the console did not stop")
		}
	})
	return c
}

// stateText is every file the console wrote in its state directory.
func (c *managedConsole) stateText(t *testing.T, under string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(c.state, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, under) {
			data, _ := os.ReadFile(p)
			b.Write(data)
			b.WriteString("\n")
		}
		return nil
	})
	return b.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A shadow profile beyond [lockhttp.bounds] mode is refused at start, with
// the line that cites the managed key and no prompt, and audited.
func TestManagedRefusesShadowAtStart(t *testing.T) {
	setRuntime(t)
	placeManaged(t, managedBounds)
	h := &human{answers: make(chan string, 8)}
	c := runManagedConsole(t, h, "[profiles.default]\nmode = \"shadow\"\n")
	var err error
	select {
	case err = <-c.done:
		c.done <- err
	case <-c.ready:
		t.Fatalf("the console started on a policy beyond the bounds:\n%s", h.text())
	case <-time.After(10 * time.Second):
		t.Fatalf("the console neither started nor stopped:\n%s", h.text())
	}
	if !errors.Is(err, console.ErrManaged) {
		t.Fatalf("Run: %v", err)
	}
	text := h.text()
	if !strings.Contains(text, "blocked by company policy: lockhttp.bounds.mode = enforce (profile default: mode = shadow)") {
		t.Fatalf("no citing line:\n%s", text)
	}
	if strings.Contains(text, "PROMPT") {
		t.Fatalf("the human was asked:\n%s", text)
	}
	if !strings.Contains(c.stateText(t, ""), console.DecisionRefusedManaged) {
		t.Fatalf("no refused-managed record:\n%s", c.stateText(t, ""))
	}
}

// While the console runs, a profile edited to shadow is refused at the next
// poll, never pending; tightening connect_grant is accepted; the approved
// policy records the managed file's fingerprint.
func TestManagedPollRefusesLooseningAcceptsTightening(t *testing.T) {
	setRuntime(t)
	placeManaged(t, managedBounds)
	m, err := managed.Load(context.Background())
	if err != nil || m == nil {
		t.Fatalf("Load: %v %v", m, err)
	}
	h := &human{answers: make(chan string, 8)}
	c := runManagedConsole(t, h, "[profiles.default]\nconnect_grant = \"5m\"\n")
	h.answers <- "y"
	select {
	case <-c.ready:
	case err := <-c.done:
		t.Fatalf("console stopped: %v\n%s", err, h.text())
	case <-time.After(10 * time.Second):
		t.Fatalf("console not ready:\n%s", h.text())
	}
	if !strings.Contains(h.text(), "Managed by Example Corp (sha256:"+m.Fingerprint[:12]) {
		t.Fatalf("no Describe line at start:\n%s", h.text())
	}
	approved := c.stateText(t, "approved")
	if !strings.Contains(approved, `"managed_sha256": "`+m.Fingerprint+`"`) || !strings.Contains(approved, `"managed_rules"`) {
		t.Fatalf("approved policy without the managed fingerprint or rules:\n%s", approved)
	}
	prompts := strings.Count(h.text(), "PROMPT")

	// Loosened beyond the bounds: refused at the next poll, never pending.
	if err := os.WriteFile(c.cfg, []byte("[profiles.default]\nmode = \"shadow\"\nconnect_grant = \"5m\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the refusal", func() bool {
		return strings.Contains(h.text(), "policy change refused by the company's managed configuration")
	})
	if !strings.Contains(h.text(), "lockhttp.bounds.mode = enforce (profile default: mode = shadow)") {
		t.Fatalf("refusal without the citing line:\n%s", h.text())
	}
	if !strings.Contains(c.stateText(t, ""), console.DecisionRefusedManaged) {
		t.Fatal("the refused change is not audited")
	}

	// Tightened: applied at once, no prompt.
	if err := os.WriteFile(c.cfg, []byte("[profiles.default]\nconnect_grant = \"1m\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the tightened policy", func() bool {
		return strings.Contains(c.stateText(t, "approved"), `"connect_grant": 60,`)
	})
	if n := strings.Count(h.text(), "PROMPT"); n != prompts {
		t.Fatalf("the human was asked about a refused or tightened policy:\n%s", h.text())
	}
	if !strings.Contains(c.stateText(t, "approved"), `"managed_sha256": "`+m.Fingerprint+`"`) {
		t.Fatal("the tightened approval lost the managed fingerprint")
	}
}

// Through the gate: a host a managed rule denies is denied although the
// user's profile has a free rule for it.
func TestManagedRuleDeniesThroughGate(t *testing.T) {
	setRuntime(t)
	placeManaged(t, managedBounds)
	h := &human{answers: make(chan string, 8)}
	stop := startConsoleWith(t, h, policyText+`
[[profiles.default.rules]]
id = "tools"
host = "tools.test"
verdict = "free"
`)
	defer stop()
	addr, _, hub := startGate(t, backend(t))
	c := client(addr)
	resp, body := get(t, c, "GET", "http://tools.test/x", "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_RULE" || !strings.Contains(body, "managed configuration") {
		t.Fatalf("managed deny: %s %v %q", resp.Status, resp.Header, body)
	}
	if n := len(hub.Tickets()); n != 0 {
		t.Fatalf("a managed deny made %d tickets", n)
	}
	// What the managed rule does not name passes as the user wrote it.
	if resp, body := get(t, c, "GET", "http://trusted.test/a", ""); resp.StatusCode != 200 || body != "ok GET trusted.test/a " {
		t.Fatalf("trusted: %s %q", resp.Status, body)
	}
}
