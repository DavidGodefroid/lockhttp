package main

import (
	"bytes"
	"os"
	"os/user"
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

func TestInstallPrint(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "lockhttp")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	u, _ := user.Current()
	e := env{executable: bin, goos: "linux", subuid: func() (string, error) { return u.Username + ":100000:65536\n", nil }}
	code, out, errs := runEnv(t, e, "install", "--client", "agent", "--gate-uid", "10003", "--print", "--trust-binary")
	if code != exitOK || !strings.Contains(out, "allowed_uids = [10003]") || !strings.Contains(out, "usermod -aG lockhttp-clients agent") {
		t.Fatalf("install: %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = runEnv(t, e, "install", "--client", u.Username, "--gate-uid", "10003", "--rootless", "--print", "--trust-binary")
	if runtime.GOOS == "windows" {
		// Rootless Podman and Unix account names: Unix only.
	} else if code != exitOK || !strings.Contains(out, "allowed_uids = [110002]") {
		t.Fatalf("rootless: %d\n%s\n%s", code, out, errs)
	}
	if code, _, _ := runEnv(t, e, "install", "--gate-uid", "0", "--print"); code != exitUsage {
		t.Fatal("gate uid 0 accepted")
	}
	if code, _, _ := runEnv(t, e, "install", "--rootless", "--print"); code != exitUsage {
		t.Fatal("--rootless without --gate-uid accepted")
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
	if code, _, _ := runEnv(t, env{euid: func() int { return 1000 }}, "gate", "--ca-cert", "x"); code != exitUsage {
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
