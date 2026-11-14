//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/lockhttp/internal/gate"
)

// loxUpConsoleArgv is the command lockhub's `lox run` gives a lockhttp
// lock's console service, copied from lockhub internal/family/compose.go:
//
//	cmd := []string{"console"}
//	if prof := l.Profile; prof != "" || l.Type == "lockfile" { ...; cmd = append(cmd, "--profile", prof) }
//	if len(l.AllowedUIDs) > 0 { cmd = append(cmd, "--allowed-uids", ...) }
//	if g := p.RuntimeGIDs[name]; g != "" { cmd = append(cmd, "--runtime-gids", g) }
//	if !k.Gate { cmd = append(cmd, "--hub", ..., "--instance", name); ... }
//
// lockhttp is a Gate kind (its gate asks the hub; the console only serves
// the policy) and lockhub refuses allowed_uids on it: the console gets
// "console", "--profile P" when the lock names a profile, and
// "--runtime-gids G" once family.RuntimeGIDsSince names lockhttp's release
// (lockhub#212). No other hub flag. Keep this in step with lockhub: if it changes, this test says
// whether lockhttp's console still starts under lox run.
//
// This is a copy: it does not detect a change in lockhub's compose.go.
// That side is guarded by lockhub's internal/family/contract_test.go,
// which asserts the argv lox run gives the lockhttp console service.
func loxUpConsoleArgv(profile string) []string {
	return loxUpConsoleArgvGIDs(profile, "")
}

// loxUpConsoleArgvGIDs is loxUpConsoleArgv with the host's runtime gids.
func loxUpConsoleArgvGIDs(profile, gids string) []string {
	cmd := []string{"console"}
	if profile != "" {
		cmd = append(cmd, "--profile", profile)
	}
	if gids != "" {
		cmd = append(cmd, "--runtime-gids", gids)
	}
	return cmd
}

// loxUpLockConsoleArgv is what lox run gives a non-gate lock's console
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

// lockhttp console, started with the argv lox run writes for it, with or
// without --runtime-gids, starts (lockkit's policy-only console: no hub)
// and listens; the console Run gets is policy-only, with no hub option but
// the runtime gids.
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
	for _, c := range []struct{ profile, gids string }{{"", ""}, {"egress", ""}, {"", "999,4242"}, {"egress", "999"}} {
		profile := c.profile
		argv := loxUpConsoleArgvGIDs(profile, c.gids)
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
		if !got.PolicyOnly || got.Hub.Enabled() || got.OnHub != nil || got.Hub.RuntimeGIDs != c.gids {
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

// unconfined = true (lockkit#133): a non-production profile starts with
// the red banner; a production profile with it does not start.
func TestConsoleUnconfinedProfile(t *testing.T) {
	rt, err := os.MkdirTemp("/tmp", "lhrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rt) })
	t.Setenv("LOCKHTTP_RUNTIME_DIR", rt)
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte("[profiles.dev]\nunconfined = true\n\n[profiles.prod]\nproduction = true\nunconfined = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		profile string
		ok      bool
		want    string
	}{
		{"dev", true, console.UnconfinedBanner},
		{"prod", false, "unconfined is never allowed on a production profile"},
	} {
		term := &answerer{}
		e := env{tty: true, userConfig: cfg, consoleRun: func(ctx context.Context, p kit.Product, b console.Backend, o console.Options) error {
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
		code, _, errs := runEnv(t, e, loxUpConsoleArgv(c.profile)...)
		if (code == exitOK) != c.ok || !strings.Contains(term.text()+errs, c.want) {
			t.Fatalf("%s: exit %d %s\n%s", c.profile, code, errs, term.text())
		}
	}
}

// The hub flags lox run gives the other locks' consoles are not lockhttp
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

// An invalid --runtime-gids is a usage error, refused before a console runs:
// never ignored (lockhub#212).
func TestConsoleRefusesInvalidRuntimeGIDs(t *testing.T) {
	e := env{tty: true, consoleRun: func(context.Context, kit.Product, console.Backend, console.Options) error {
		t.Fatal("the console ran")
		return nil
	}}
	for _, g := range []string{"docker", "999,", ",999", "999,,4242", "-1", "999;4242", "4294967296"} {
		code, _, errs := runEnv(t, e, loxUpConsoleArgvGIDs("", g)...)
		if code != exitUsage || !strings.Contains(errs, "--runtime-gids") {
			t.Fatalf("%q: exit %d %s", g, code, errs)
		}
	}
}

// A socket peer holding one of the --runtime-gids is unconfined
// (runtime_group): a profile without unconfined = true refuses it with
// CodeUnconfined, whatever the peer reports (lockkit#133).
func TestConsoleRuntimeGroupPeerRefused(t *testing.T) {
	rt, err := os.MkdirTemp("/tmp", "lhrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rt) })
	t.Setenv("LOCKHTTP_RUNTIME_DIR", rt)
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte("[profiles.default]\nhold = \"5s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	term := &answerer{}
	var callErr error
	e := env{tty: true, userConfig: cfg, consoleRun: func(ctx context.Context, p kit.Product, b console.Backend, o console.Options) error {
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
		o.Ready = func(string) {
			go func() {
				defer cancel()
				_, callErr = (&gate.LockkitConsole{Profile: "default"}).Policy(ctx)
			}()
		}
		return console.Run(ctx, p, b, o)
	}}
	// The test's own gid: this process is the socket's peer.
	code, _, errs := runEnv(t, e, loxUpConsoleArgvGIDs("", "4242,"+strconv.Itoa(os.Getgid()))...)
	if code != exitOK {
		t.Fatalf("exit %d %s\n%s", code, errs, term.text())
	}
	var rpc *ipc.RPCError
	if !errors.As(callErr, &rpc) || rpc.Code != ipc.CodeUnconfined || !strings.Contains(rpc.Message, "runtime_group") {
		t.Fatalf("runtime group peer: %v\n%s", callErr, term.text())
	}
	if !strings.Contains(term.text(), "refused an unconfined agent") || !strings.Contains(term.text(), "runtime_group") {
		t.Fatalf("the console did not show the refusal:\n%s", term.text())
	}
}
