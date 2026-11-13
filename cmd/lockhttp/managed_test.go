//go:build lockfamily_managed_test

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/verbs"
)

const managedGolden = `version = 1
organisation = "Example Corp"

[lockhttp.bounds]
mode = "enforce"
connect_grant = "5m"
trusted = ["*.example.com"]
deny = ["paste.example.org"]

[[lockhttp.bounds.rules]]
id = "no-tools"
host = "tools.example.com"
verdict = "deny"

[lockhttp.defaults]
heuristics = "enforce"

[lockhttp.profiles.corp]
connect_grant = "5m"
deny = ["paste.example.org"]
`

// placeManaged makes managed.Load read text (test builds only) and
// returns its path and fingerprint.
func placeManaged(t *testing.T, text string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
	sum := sha256.Sum256([]byte(text))
	return path, hex.EncodeToString(sum[:])
}

func consoleConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManagedShowNoFile(t *testing.T) {
	managed.SetTestPath("")
	code, out, errs := runEnv(t, env{}, "managed", "show")
	if code != exitOK || out != "no managed configuration\n" || errs != "" {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, out, _ = runEnv(t, env{userConfig: consoleConfig(t, "[profiles.dev]\nmode = \"shadow\"\n")}, "managed", "check")
	if code != exitOK || out != "no managed configuration\n" {
		t.Fatalf("check without a file: %d %q", code, out)
	}
}

func TestManagedShowFile(t *testing.T) {
	path, fp := placeManaged(t, managedGolden)
	code, out, errs := runEnv(t, env{}, "managed", "show")
	want := `path: ` + path + `
organisation: Example Corp
fingerprint: sha256:` + fp + `
signed: no
bounds:
  mode = enforce
  connect_grant = 300s
  trusted = *.example.com (allowed)
  deny = paste.example.org (required)
  rule no-tools: deny * tools.example.com all-containers
defaults:
  heuristics = enforce
profiles:
  corp
`
	if code != exitOK || out != want || errs != "" {
		t.Fatalf("%d %q\n--- got\n%s--- want\n%s", code, errs, out, want)
	}
}

func TestManagedShowRefusedFile(t *testing.T) {
	placeManaged(t, "version = 2\n")
	code, out, errs := runEnv(t, env{}, "managed", "show")
	if code != exitUsage || out != "" || !strings.HasPrefix(errs, "lockhttp managed: managed: ") || !strings.Contains(errs, "version 2 is not supported") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// A [lockhttp] section lockhttp refuses is a refused file too.
	placeManaged(t, "version = 1\n[lockhttp.bounds]\nhold = \"10s\"\n")
	code, _, errs = runEnv(t, env{}, "managed", "show")
	if code != exitUsage || !strings.Contains(errs, `unknown key "hold"`) {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestManagedCheckOK(t *testing.T) {
	placeManaged(t, managedGolden)
	cfg := consoleConfig(t, "[profiles.dev]\ntrusted = [\"api.example.com\"]\nconnect_grant = \"1m\"\ndeny = [\"paste.example.org\"]\n")
	code, out, errs := runEnv(t, env{userConfig: cfg}, "managed", "check")
	want := "profile corp: within the company's managed configuration\nprofile dev: within the company's managed configuration\n"
	if code != exitOK || out != want || errs != "" {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, out, _ = runEnv(t, env{userConfig: cfg}, "managed", "check", "--profile", "dev")
	if code != exitOK || out != "profile dev: within the company's managed configuration\n" {
		t.Fatalf("--profile: %d %q", code, out)
	}
}

func TestManagedCheckViolation(t *testing.T) {
	placeManaged(t, managedGolden)
	cfg := consoleConfig(t, "[profiles.dev]\nmode = \"shadow\"\ntrusted = [\"evil.example.org\"]\n")
	code, out, errs := runEnv(t, env{userConfig: cfg}, "managed", "check", "--profile", "dev")
	want := `blocked by company policy: lockhttp.bounds.mode = enforce (profile dev: mode = shadow)
blocked by company policy: lockhttp.bounds.connect_grant = 300s (profile dev: connect_grant = 600s)
blocked by company policy: lockhttp.bounds.trusted does not allow evil.example.org (profile dev: trusted + evil.example.org)
blocked by company policy: lockhttp.bounds.deny requires paste.example.org (profile dev: deny - paste.example.org)
`
	if code != exitUsage || out != want || errs != "" {
		t.Fatalf("%d %q\n--- got\n%s--- want\n%s", code, errs, out, want)
	}
	// A file profile of a managed name is refused, with exit 3.
	cfg = consoleConfig(t, "[profiles.corp]\n")
	code, out, _ = runEnv(t, env{userConfig: cfg}, "managed", "check")
	if code != exitUsage || !strings.HasPrefix(out, "blocked by company policy: ") || !strings.Contains(out, `profile "corp"`) {
		t.Fatalf("redefined managed profile: %d %q", code, out)
	}
	// A refused file: the lockkit error, exit 3.
	placeManaged(t, "version = 2\n")
	code, out, _ = runEnv(t, env{userConfig: cfg}, "managed", "check")
	if code != exitUsage || !strings.HasPrefix(out, "blocked by company policy: managed: ") {
		t.Fatalf("refused file: %d %q", code, out)
	}
}

func TestDoctorManagedLine(t *testing.T) {
	dir := t.TempDir()
	managed.SetTestPath("")
	_, d := doctorJSON(t, env{cwd: dir})
	if c, ok := findCheck(d, "managed"); !ok || c.Status != verbs.StatusOK || c.Detail != "no managed configuration" {
		t.Fatalf("no file: %+v", c)
	}
	_, fp := placeManaged(t, managedGolden)
	_, d = doctorJSON(t, env{cwd: dir})
	if c, _ := findCheck(d, "managed"); c.Status != verbs.StatusOK || c.Detail != "Managed by Example Corp (sha256:"+fp[:12]+")" {
		t.Fatalf("file: %+v", c)
	}
	placeManaged(t, "version = 2\n")
	_, d = doctorJSON(t, env{cwd: dir})
	if c, _ := findCheck(d, "managed"); c.Status != verbs.StatusFail || !strings.Contains(c.Detail, "version 2 is not supported") {
		t.Fatalf("refused file: %+v", c)
	}
	// The project's policy beyond the bounds fails the policy check.
	placeManaged(t, managedGolden)
	if code, _, errs := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive", "--profile", "web"); code != exitOK {
		t.Fatal(errs)
	}
	_, d = doctorJSON(t, env{cwd: dir})
	if c, _ := findCheck(d, "policy"); c.Status != verbs.StatusFail || !strings.Contains(c.Detail, "blocked by company policy: lockhttp.bounds.") {
		t.Fatalf("policy beyond the bounds: %+v", c)
	}
	// Human output: the Describe line.
	_, out, _ := runEnv(t, env{cwd: dir}, "doctor")
	if !strings.Contains(out, "managed: Managed by Example Corp (sha256:") {
		t.Fatalf("human output: %q", out)
	}
}
