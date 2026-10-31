package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, cwd: t.TempDir()}, args)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runArgs(t, "version")
	if code != exitOK || out != "lockhttp dev\n" {
		t.Fatalf("version: %d %q", code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errs := runArgs(t, "nope")
	if code != exitUsage || !strings.Contains(errs, `unknown command "nope"`) {
		t.Fatalf("unknown: %d %q", code, errs)
	}
}

func TestNoArgs(t *testing.T) {
	if code, _, _ := runArgs(t); code != exitUsage {
		t.Fatalf("no args: %d", code)
	}
}

func runEnv(t *testing.T, e env, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	e.stdout, e.stderr = &out, &errb
	if e.stdin == nil {
		e.stdin = strings.NewReader("")
	}
	if e.cwd == "" {
		e.cwd = t.TempDir()
	}
	code := run(e, args)
	return code, out.String(), errb.String()
}

func TestInstallRefused(t *testing.T) {
	for _, c := range []string{"install", "setup"} {
		code, _, errs := runEnv(t, env{}, c, "--yes")
		if code != exitUsage || !strings.Contains(errs, "runs in Docker") {
			t.Fatalf("%s: %d %s", c, code, errs)
		}
	}
}

func TestPolicyCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if code, _, _ := runEnv(t, env{}, "policy", "show", "--config", path); code != exitFail {
		t.Fatal("show without a file")
	}
	if code, _, _ := runEnv(t, env{}, "init", "--config", path); code != exitOK {
		t.Fatal("init")
	}
	code, out, _ := runEnv(t, env{}, "policy", "show", "--config", path)
	if code != exitOK || !strings.Contains(out, "[profiles.default]") {
		t.Fatalf("show: %d %s", code, out)
	}
	if _, out, _ := runEnv(t, env{}, "policy", "path", "--config", path); strings.TrimSpace(out) != path {
		t.Fatalf("path: %q", out)
	}
	good := env{editor: func(p string) error {
		b, _ := os.ReadFile(p)
		return os.WriteFile(p, append(b, []byte("\n[profiles.lab]\n")...), 0o600)
	}}
	if code, out, errs := runEnv(t, good, "policy", "edit", "--config", path); code != exitOK || !strings.Contains(out, "saved") {
		t.Fatalf("edit: %d %s %s", code, out, errs)
	}
	bad := env{editor: func(p string) error { return os.WriteFile(p, []byte("[profiles.default]\nmode = \"loose\"\n"), 0o600) }}
	if code, _, errs := runEnv(t, bad, "policy", "edit", "--config", path); code != exitUsage || !strings.Contains(errs, "does not parse") {
		t.Fatalf("broken edit: %d %s", code, errs)
	}
	if code, _, _ := runEnv(t, env{}, "policy", "nope"); code != exitUsage {
		t.Fatal("unknown subcommand")
	}
}

func TestInitWritesValidPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg", "config.toml")
	code, out, errs := runEnv(t, env{}, "init", "--config", path, "--trusted", "example.org,.corp.example")
	if code != exitOK || !strings.Contains(out, "wrote") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"*.corp.example"`) {
		t.Fatalf("imports missing:\n%s", b)
	}
	fi, _ := os.Stat(path)
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if code, _, _ := runEnv(t, env{}, "init", "--config", path); code != exitFail {
		t.Fatal("overwrote without --force")
	}
	if code, _, _ := runEnv(t, env{}, "init", "--config", path, "--force", "--profile", "lab"); code != exitOK {
		t.Fatal("--force --profile")
	}
	code, out, _ = runEnv(t, env{}, "doctor", "--config", path, "--profile", "lab")
	if !strings.Contains(out, "profile lab") {
		t.Fatalf("doctor: %d %s", code, out)
	}
}

func TestGateRefusesRoot(t *testing.T) {
	code, _, errs := runEnv(t, env{euid: func() int { return 0 }}, "gate", "--listen", "127.0.0.1:0")
	if code != exitUsage || !strings.Contains(errs, "refused as root") {
		t.Fatalf("root gate: %d %s", code, errs)
	}
	hub := []string{"--hub", "http://127.0.0.1:8443", "--hub-key-file", writeHubPub(t), "--instance", "egress", "--home", t.TempDir()}
	if code, _, errs := runEnv(t, env{euid: func() int { return 1000 }}, append([]string{"gate", "--ca-cert", "x"}, hub...)...); code != exitUsage || !strings.Contains(errs, "go together") {
		t.Fatal("--ca-cert without --signer accepted")
	}
	if code, _, _ := runEnv(t, env{}, "gate", "--check", "--listen", "127.0.0.1:1"); code != exitFail {
		t.Fatal("check on a closed port")
	}
}

func TestCAInitAndSignerKeyMode(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := runEnv(t, env{}, "ca", "init", "--dir", dir, "--name", "t"); code != exitOK {
		t.Fatalf("ca init: %s", errs)
	}
	key := filepath.Join(dir, "ca-key.pem")
	_ = os.Chmod(key, 0o644)
	code, _, errs := runEnv(t, env{}, "signer", "--ca-cert", filepath.Join(dir, "ca.pem"), "--ca-key", key, "--listen", filepath.Join(dir, "s.sock"))
	if code != exitUsage || !strings.Contains(errs, "readable by others") {
		t.Fatalf("signer with a readable key: %d %s", code, errs)
	}
	code, out, _ := runEnv(t, env{}, "doctor", "--ca-cert", filepath.Join(dir, "ca.pem"), "--config", filepath.Join(dir, "none.toml"))
	if !strings.Contains(out, "CA valid until") {
		t.Fatalf("doctor CA: %d %s", code, out)
	}
}

func TestConsoleNeedsTTY(t *testing.T) {
	if code, _, errs := runEnv(t, env{}, "console"); code != exitUsage || !strings.Contains(errs, "terminal") {
		t.Fatalf("console without tty: %d %s", code, errs)
	}
}

// The gate runs hub-attached only: without its hub flags it does not
// start, and it says that `lox up` (through lea) gives them.
func TestGateHubOnly(t *testing.T) {
	gate := env{euid: func() int { return 1000 }}
	for _, args := range [][]string{nil, {"--upstream", "http://127.0.0.1:3128"}, {"--sources", "s.json", "--profile", "p"}} {
		code, out, errs := runEnv(t, gate, append([]string{"gate", "--listen", "127.0.0.1:0"}, args...)...)
		if code != exitUsage || out != "" || !strings.Contains(errs, "launched by `lox up` only") || !strings.Contains(errs, "--hub") {
			t.Errorf("%v: %d %q %s", args, code, out, errs)
		}
	}
}

// The hub flags go together, and the instance key comes from the gate's
// own volume: hub-key prints the public key the hub pins.
func TestGateHubFlags(t *testing.T) {
	gate := env{euid: func() int { return 1000 }}
	for _, args := range [][]string{
		{"--hub", "http://lockhub:8443"},
		{"--hub", "http://lockhub:8443", "--hub-key-file", "k"},
		{"--instance", "egress"},
		{"--hub-net", "10.89.0.0/24"},
		{"--hub", "http://lockhub:8443", "--hub-key-file", "k", "--instance", "Not_Valid"},
		{"--hub-net", "nope"},
		{"--facade-keys-file", "facades.json"},
	} {
		code, _, errs := runEnv(t, gate, append([]string{"gate", "--listen", "127.0.0.1:0"}, args...)...)
		if code != exitUsage {
			t.Errorf("%v: %d %s", args, code, errs)
		}
	}
	home := t.TempDir()
	code, pub, errs := runEnv(t, env{}, "hub-key", "--instance", "egress", "--home", home)
	if code != exitOK || len(strings.TrimSpace(pub)) != 44 {
		t.Fatalf("hub-key: %d %q %s", code, pub, errs)
	}
	if _, again, _ := runEnv(t, env{}, "hub-key", "--instance", "egress", "--home", home); again != pub {
		t.Fatalf("hub-key changed the key: %q then %q", pub, again)
	}
	if fi, err := os.Stat(filepath.Join(home, "hub", "egress.key")); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("instance key: %v %v", fi, err)
	}
	// A bad pinned hub key is refused before the gate listens.
	bad := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(bad, []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs = runEnv(t, gate, "gate", "--listen", "127.0.0.1:0", "--hub", "http://lockhub:8443", "--hub-key-file", bad, "--instance", "egress", "--home", home)
	if code != exitUsage || !strings.Contains(errs, "public key") {
		t.Fatalf("bad hub key: %d %s", code, errs)
	}
	// So are facade keys that do not parse.
	hubPub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := filepath.Join(t.TempDir(), "hub.pub")
	facades := filepath.Join(t.TempDir(), "facades.json")
	if os.WriteFile(good, []byte(base64.StdEncoding.EncodeToString(hubPub)+"\n"), 0o644) != nil || os.WriteFile(facades, []byte("[{]"), 0o644) != nil {
		t.Fatal("cannot write the key files")
	}
	code, _, errs = runEnv(t, gate, "gate", "--listen", "127.0.0.1:0", "--hub", "http://127.0.0.1:8443", "--hub-key-file", good, "--instance", "egress", "--home", home,
		"--facade-keys-file", facades)
	if code != exitUsage || !strings.Contains(errs, "facades.json") {
		t.Fatalf("bad facade keys: %d %s", code, errs)
	}
}

func TestHubAddrs(t *testing.T) {
	if got := hubAddrs("10.89.0.7"); len(got) != 1 || got[0].String() != "10.89.0.7/32" {
		t.Fatalf("IP hub: %v", got)
	}
	if got := hubAddrs("localhost"); len(got) == 0 {
		t.Fatalf("localhost: %v", got)
	}
}

// A hub whose host does not resolve and no --hub-net: the gate does not
// start, it could not refuse the hub's addresses.
func TestGateHubNeedsAnAddress(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(key, []byte("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runEnv(t, env{euid: func() int { return 1000 }}, "gate", "--listen", "127.0.0.1:0", "--hub", "http://no-such-hub.invalid:8443",
		"--hub-key-file", key, "--instance", "egress", "--home", home)
	if code != exitUsage || !strings.Contains(errs, "--hub-net") {
		t.Fatalf("unresolvable hub: %d %s", code, errs)
	}
}

// An http:// hub on a network of its own needs --hub-plain-http; a public
// http:// hub is refused even with it.
func TestGateHubPlainHTTP(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(key, []byte("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gate := env{euid: func() int { return 1000 }}
	base := []string{"gate", "--listen", "127.0.0.1:0", "--hub-key-file", key, "--instance", "egress", "--home", home, "--hub-net", "10.89.0.0/24"}
	for _, c := range []struct {
		url   string
		plain bool
		want  string
	}{
		{"http://lockhub:8443", false, "--hub-plain-http"},
		{"http://hub.example.com:8443", true, "--hub-plain-http is only for"},
	} {
		args := append(append([]string{}, base...), "--hub", c.url)
		if c.plain {
			args = append(args, "--hub-plain-http")
		}
		code, _, errs := runEnv(t, gate, args...)
		if code != exitUsage || !strings.Contains(errs, c.want) {
			t.Errorf("%s plain=%v: %d %s", c.url, c.plain, code, errs)
		}
	}
}
