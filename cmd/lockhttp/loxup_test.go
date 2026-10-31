//go:build unix

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// loxUpConsoleArgv is the command lockhub's `lox up` gives a lockhttp
// lock's console service, copied from lockhub internal/family/compose.go:
//
//	cmd := []string{"console"}
//	if prof := l.Profile; prof != "" || l.Type == "lockfile" { ...; cmd = append(cmd, "--profile", prof) }
//	if len(l.AllowedUIDs) > 0 { cmd = append(cmd, "--allowed-uids", ...) }
//	if !k.Gate { cmd = append(cmd, "--hub", ..., "--instance", name); ... }
//
// lockhttp is a Gate kind (its gate asks the hub; the console only serves
// the policy) and lockhub refuses allowed_uids on it: the console gets
// "console" and, when the lock names a profile, "--profile P". No hub
// flag. Keep this in step with lockhub: if it changes, this test says
// whether lockhttp's console still starts under lox up.
//
// This is a copy: it does not detect a change in lockhub's compose.go.
// That side is guarded by lockhub's internal/family/contract_test.go,
// which asserts the argv lox up gives the lockhttp console service.
func loxUpConsoleArgv(profile string) []string {
	cmd := []string{"console"}
	if profile != "" {
		cmd = append(cmd, "--profile", profile)
	}
	return cmd
}

// loxUpLockConsoleArgv is what lox up gives a non-gate lock's console
// (locksql, lockmq, lockfile): the hub flags lockhttp's console never gets.
func loxUpLockConsoleArgv(instance string) []string {
	return []string{"console", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/lockfamily/hub.pub", "--instance", instance}
}

// answerer is the console's terminal: y to every prompt.
type answerer struct {
	mu    sync.Mutex
	lines []string
}

func (a *answerer) Println(s string) { a.mu.Lock(); a.lines = append(a.lines, s); a.mu.Unlock() }
func (a *answerer) Ask(context.Context, string, time.Duration) (string, bool) {
	return "y", true
}
func (a *answerer) AskSecret(context.Context, string) ([]byte, error) { return nil, io.EOF }
func (a *answerer) text() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.lines, "\n")
}

// lockhttp console, started with the argv lox up writes for it, starts
// (lockkit's policy-only console: no hub) and listens; the console Run
// gets is policy-only, with no hub option.
func TestConsoleStartsAsLoxUpRunsIt(t *testing.T) {
	rt, err := os.MkdirTemp("/tmp", "lhrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rt) })
	t.Setenv("LOCKHTTP_RUNTIME_DIR", rt)
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte("[profiles.default]\nhold = \"5s\"\n\n[profiles.egress]\nhold = \"5s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"", "egress"} {
		argv := loxUpConsoleArgv(profile)
		term := &answerer{}
		var got console.Options
		e := env{tty: true, userConfig: cfg, consoleRun: func(ctx context.Context, p kit.Product, b console.Backend, o console.Options) error {
			got = o
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			o.IO, o.TTY, o.StateDir, o.Quantum = term, nil, t.TempDir(), -1
			o.Harden = func() error { return nil }
			o.Isolation = &console.IsolationEnv{
				AllowSameUser: true,
				LoadSys:       func() (*sysconf.Config, error) { return nil, nil },
				Display:       func() sysconf.Display { return sysconf.Display{} },
				UID:           os.Getuid,
			}
			o.Ready = func(string) { cancel() }
			return console.Run(ctx, p, b, o)
		}}
		code, _, errs := runEnv(t, e, argv...)
		if code != exitOK || !strings.Contains(term.text(), "Listening on") {
			t.Fatalf("%v: exit %d %s\n%s", argv, code, errs, term.text())
		}
		if !got.PolicyOnly || got.Hub.Enabled() || got.OnHub != nil {
			t.Fatalf("%v: options %+v", argv, got)
		}
		want := profile
		if want == "" {
			want = "default"
		}
		if got.Profile != want {
			t.Fatalf("%v: profile %q", argv, got.Profile)
		}
	}
}

// The hub flags lox up gives the other locks' consoles are not lockhttp
// console's: it refuses them (usage) before running a console.
func TestConsoleRefusesHubFlags(t *testing.T) {
	e := env{tty: true, consoleRun: func(context.Context, kit.Product, console.Backend, console.Options) error {
		t.Fatal("the console ran")
		return nil
	}}
	code, _, errs := runEnv(t, e, loxUpLockConsoleArgv("web")...)
	if code != exitUsage || !strings.Contains(errs, "-hub") {
		t.Fatalf("exit %d %s", code, errs)
	}
}
