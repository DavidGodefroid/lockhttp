package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/agentwire"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
)

// oneJSON decodes out, which must be exactly one line of JSON, into v and
// returns its keys.
func oneJSON(t *testing.T, out string, v any) []string {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("stdout is not one line: %q", out)
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("stdout is not JSON: %v: %q", err, out)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(out), &m)
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func projectConfig(dir string) string { return filepath.Join(dir, ".lockhttp", "config.toml") }

// lsAll lists every path under dir.
func lsAll(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error {
		out = append(out, p)
		return nil
	})
	return out
}

// init <agent> accepts every agent, writes nothing and exits 0; anything
// else is a usage error, the old --trusted included.
func TestInitAgent(t *testing.T) {
	dir := t.TempDir()
	for _, a := range agentwire.Agents() {
		code, out, errs := runEnv(t, env{cwd: dir}, "init", a)
		if code != exitOK || !strings.Contains(out, "nothing to write for "+a) {
			t.Errorf("init %s: %d %q %q", a, code, out, errs)
		}
	}
	if got := lsAll(t, dir); len(got) != 1 {
		t.Errorf("init wrote files: %v", got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "name the agent"},
		{[]string{"nope"}, "unknown agent"},
		{[]string{"claude", "codex"}, "one agent"},
		{[]string{"--trusted", "a.com"}, "profile add"},
		{[]string{"claude", "--force"}, "no flag"},
	} {
		code, out, errs := runEnv(t, env{cwd: dir}, append([]string{"init"}, tc.args...)...)
		if code != exitUsage || out != "" || !strings.Contains(errs, tc.want) {
			t.Errorf("init %v: %d %q %q", tc.args, code, out, errs)
		}
	}
}

// profile add --non-interactive --json writes the default policy in the
// project's .lockhttp/config.toml and prints one verbs.Profile line.
func TestProfileAddNonInteractive(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive", "--json", "--profile", "web", "--trusted", "example.org .corp.example")
	if code != exitOK {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	var p verbs.Profile
	keys := oneJSON(t, out, &p)
	path := projectConfig(dir)
	if want := (verbs.Profile{Lock: "lockhttp", Profile: "web", Config: path}); p != want {
		t.Fatalf("profile %+v, want %+v", p, want)
	}
	if strings.Join(keys, ",") != "config,lock,production,profile" {
		t.Fatalf("keys %v: no credentials for a target without a secret", keys)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse(b, path, "web")
	if err != nil || pol.Production || !pol.Trusts("example.org") || !pol.Trusts("a.corp.example") || !pol.Trusts("go.dev") {
		t.Fatalf("policy %+v %v", pol, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", st.Mode().Perm())
		}
	}

	// Without --profile: the default, reported in the JSON; without
	// --json: human text, no JSON.
	code, out, errs = runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive")
	if code != exitOK || !strings.Contains(out, "added profile default") || strings.HasPrefix(out, "{") {
		t.Fatalf("default: %d %q %q", code, out, errs)
	}
	b2, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b2), string(b)) {
		t.Fatal("adding a profile rewrote the others")
	}
	if names, err := policy.Profiles(b2, path); err != nil || strings.Join(names, ",") != "default,web" {
		t.Fatalf("profiles %v %v", names, err)
	}

	// A production profile, from a subdirectory of the project.
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runEnv(t, env{cwd: sub}, "profile", "add", "--non-interactive", "--json", "--profile", "prod.eu", "--production")
	if code != exitOK {
		t.Fatalf("production: %d %q %q", code, out, errs)
	}
	oneJSON(t, out, &p)
	if !p.Production || p.Config != path {
		t.Fatalf("production: %+v", p)
	}
	b3, _ := os.ReadFile(path)
	if pol, err := policy.Parse(b3, path, "prod.eu"); err != nil || !pol.Production {
		t.Fatalf("production policy %+v %v", pol, err)
	}
}

// An existing profile is never rewritten: code exists, nothing written.
func TestProfileAddExists(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive", "--profile", "web"); code != exitOK {
		t.Fatal(errs)
	}
	path := projectConfig(dir)
	before, _ := os.ReadFile(path)
	for _, args := range [][]string{
		{"--profile", "web"},
		{"--profile", "web", "--production", "--trusted", "other.example"},
	} {
		code, out, _ := runEnv(t, env{cwd: dir}, append([]string{"profile", "add", "--non-interactive", "--json"}, args...)...)
		var e verbs.Error
		keys := oneJSON(t, out, &e)
		if code != exitFail || e.Code != verbs.CodeExists || e.Lock != "lockhttp" || strings.Join(keys, ",") != "code,error,lock" {
			t.Errorf("%v: %d %+v", args, code, e)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("%v: the config was rewritten", args)
		}
	}
}

// No form of profile add takes a secret: a flag named like one, a value
// that embeds a password, a positional argument; the errors never quote
// the value and nothing is written.
func TestProfileAddRefusesSecrets(t *testing.T) {
	const secret = "hunter2xyz"
	for _, tc := range []struct {
		args []string
		code string
	}{
		{[]string{"--password", secret}, verbs.CodeSecret},
		{[]string{"--vault-token", secret}, verbs.CodeSecret},
		{[]string{"--api-secret=" + secret}, verbs.CodeSecret},
		{[]string{"--trusted", "user:" + secret + "@example.org"}, verbs.CodeSecret},
		{[]string{"--trusted", "password=" + secret}, verbs.CodeSecret},
		{[]string{"--profile", "web", secret}, verbs.CodeUsage},
		{[]string{"--profile", "web", "--password=" + secret}, verbs.CodeSecret},
		{[]string{"--profile", "x\x1b" + secret}, verbs.CodeUsage},
		{[]string{"--credentials", "ask"}, verbs.CodeUsage},
		{[]string{"--profile", secret + "/x"}, verbs.CodeUsage},
		{[]string{"--trusted", "1.2.3.4 " + secret + ".invalid/x"}, verbs.CodeUsage},
		{[]string{"--project", "/nonexistent/" + secret}, verbs.CodeUsage},
		{[]string{"--production=" + secret}, verbs.CodeUsage},
	} {
		for _, interactive := range []bool{false, true} {
			dir := t.TempDir()
			args := append([]string{"profile", "add", "--json"}, tc.args...)
			if !interactive {
				args = append([]string{"profile", "add", "--non-interactive", "--json"}, tc.args...)
			}
			code, out, errs := runEnv(t, env{cwd: dir, tty: interactive, stdin: strings.NewReader("\n\n\n")}, args...)
			var e verbs.Error
			oneJSON(t, out, &e)
			if code != exitUsage || e.Code != tc.code {
				t.Errorf("%v (interactive %v): %d %+v", tc.args, interactive, code, e)
			}
			if strings.Contains(out, secret) || strings.Contains(errs, secret) {
				t.Errorf("%v: the value is quoted: %q %q", tc.args, out, errs)
			}
			if got := lsAll(t, dir); len(got) != 1 {
				t.Errorf("%v: wrote %v", tc.args, got)
			}
		}
	}
}

// Other usage errors: a production name that cannot be typed as an
// approval, no terminal without --non-interactive, a config that does not
// parse (failed, untouched), a bad subcommand.
func TestProfileAddUsage(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		e    env
		args []string
		code string
	}{
		{env{}, []string{"add", "--non-interactive", "--json", "--profile", "y", "--production"}, verbs.CodeUsage},
		{env{}, []string{"add", "--json", "--profile", "web"}, verbs.CodeUsage},
		{env{}, []string{"list", "--json"}, verbs.CodeUsage},
		{env{}, []string{"--json"}, verbs.CodeUsage},
	} {
		tc.e.cwd = dir
		code, out, errs := runEnv(t, tc.e, append([]string{"profile"}, tc.args...)...)
		var e verbs.Error
		oneJSON(t, out, &e)
		if code != exitUsage || e.Code != tc.code || !strings.Contains(errs, "usage: lockhttp profile add") {
			t.Errorf("%v: %d %+v %q", tc.args, code, e, errs)
		}
	}
	if got := lsAll(t, dir); len(got) != 1 {
		t.Errorf("wrote %v", got)
	}
	path := projectConfig(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	broken := "[profiles.default]\nmode = \"loose\"\n[nope\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive", "--json", "--profile", "web")
	var e verbs.Error
	oneJSON(t, out, &e)
	if code != exitFail || e.Code != verbs.CodeFailed {
		t.Errorf("broken config: %d %+v", code, e)
	}
	if b, _ := os.ReadFile(path); string(b) != broken {
		t.Error("a broken config was rewritten")
	}
}

// --project names the project, relative to the current directory.
func TestProfileAddProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive", "--json", "--project", "proj")
	if code != exitOK {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	var p verbs.Profile
	oneJSON(t, out, &p)
	if p.Config != projectConfig(filepath.Join(dir, "proj")) || p.Profile != "default" {
		t.Fatalf("%+v", p)
	}
}

// On a terminal, profile add asks for what the flags did not give, on
// stderr; it never asks for a secret.
func TestProfileAddInteractive(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := runEnv(t, env{cwd: dir, tty: true, stdin: strings.NewReader("lab\ny\nexample.org, .corp.example\n")}, "profile", "add")
	if code != exitOK || !strings.Contains(out, "added profile lab") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	for _, q := range []string{"Profile name", "Production profile", "Hosts to trust"} {
		if !strings.Contains(errs, q) {
			t.Errorf("not asked %q: %q", q, errs)
		}
	}
	if strings.Contains(strings.ToLower(errs), "password") || strings.Contains(strings.ToLower(errs), "secret") {
		t.Errorf("asks for a secret: %q", errs)
	}
	path := projectConfig(dir)
	b, _ := os.ReadFile(path)
	if pol, err := policy.Parse(b, path, "lab"); err != nil || !pol.Production || !pol.Trusts("x.corp.example") {
		t.Fatalf("%+v %v", pol, err)
	}

	// The flags given are not asked; --json still prints one line.
	code, out, errs = runEnv(t, env{cwd: dir, tty: true, stdin: strings.NewReader("\n")}, "profile", "add", "--json", "--profile", "web", "--production")
	var p verbs.Profile
	oneJSON(t, out, &p)
	if code != exitOK || p.Profile != "web" || !p.Production || strings.Contains(errs, "Profile name") || strings.Contains(errs, "Production profile") {
		t.Fatalf("%d %+v %q", code, p, errs)
	}

	// An existing name is refused before the other questions.
	code, _, errs = runEnv(t, env{cwd: dir, tty: true, stdin: strings.NewReader("lab\n")}, "profile", "add")
	if code != exitFail || strings.Contains(errs, "Production profile") {
		t.Fatalf("existing: %d %q", code, errs)
	}

	// The input ending before an answer is a usage error.
	if code, _, errs := runEnv(t, env{cwd: t.TempDir(), tty: true}, "profile", "add"); code != exitUsage || !strings.Contains(errs, "no answer") {
		t.Fatalf("EOF: %d %q", code, errs)
	}
}

// doctor's flag rules: --yes without --fix, and --fix without a terminal
// and without --yes, are usage errors; with --json, a verbs.Error (the
// code key), not a verbs.Doctor.
func TestDoctorFlagRules(t *testing.T) {
	for _, tc := range []struct {
		e    env
		args []string
		want string
	}{
		{env{}, []string{"--yes"}, "--yes goes with --fix"},
		{env{tty: true}, []string{"--yes"}, "--yes goes with --fix"},
		{env{}, []string{"--fix"}, "add --yes"},
		{env{}, []string{"--nope"}, "unknown flag"},
		{env{}, []string{"extra"}, "positional"},
	} {
		code, out, errs := runEnv(t, tc.e, append([]string{"doctor", "--json"}, tc.args...)...)
		var e verbs.Error
		keys := oneJSON(t, out, &e)
		if code != exitUsage || e.Code != verbs.CodeUsage || !slices.Contains(keys, "code") || slices.Contains(keys, "checks") || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: %d %+v %q", tc.args, code, e, errs)
		}
	}
}

func doctorJSON(t *testing.T, e env, args ...string) (int, verbs.Doctor) {
	t.Helper()
	code, out, errs := runEnv(t, e, append([]string{"doctor", "--json"}, args...)...)
	var d verbs.Doctor
	keys := oneJSON(t, out, &d)
	if !slices.Contains(keys, "checks") || slices.Contains(keys, "code") {
		t.Fatalf("not a verbs.Doctor: %q %q", out, errs)
	}
	return code, d
}

func findCheck(d verbs.Doctor, name string) (verbs.Check, bool) {
	for _, c := range d.Checks {
		if c.Check == name {
			return c, true
		}
	}
	return verbs.Check{}, false
}

// doctor checks the project of the current directory: without a policy it
// fails and names profile add; with one it checks every profile, or the
// one named.
func TestDoctorProject(t *testing.T) {
	dir := t.TempDir()
	code, d := doctorJSON(t, env{cwd: dir})
	if c, _ := findCheck(d, "policy"); code != exitFail || d.OK || c.Status != verbs.StatusFail || c.Fix != "lockhttp profile add" {
		t.Fatalf("no project: %d %+v", code, d)
	}
	if d.Lock != "lockhttp" || d.Fixed == nil {
		t.Fatalf("shape: %+v", d)
	}
	for _, name := range []string{"web", "lab"} {
		if code, _, errs := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive", "--profile", name); code != exitOK {
			t.Fatal(errs)
		}
	}
	_, d = doctorJSON(t, env{cwd: dir})
	var details []string
	for _, c := range d.Checks {
		if c.Check == "policy" {
			if c.Status != verbs.StatusOK {
				t.Errorf("policy check: %+v", c)
			}
			details = append(details, c.Detail)
		}
	}
	if len(details) != 2 || !strings.Contains(details[0], "profile lab") || !strings.Contains(details[1], "profile web") {
		t.Fatalf("policy checks: %v", details)
	}
	if c, ok := findCheck(d, "agent"); !ok || c.Status != verbs.StatusOK {
		t.Errorf("agent check: %+v", d.Checks)
	}
	_, d = doctorJSON(t, env{cwd: dir}, "--profile", "nope")
	if c, _ := findCheck(d, "policy"); c.Status != verbs.StatusFail {
		t.Errorf("unknown profile: %+v", c)
	}
	// Human output: one line per check.
	_, out, _ := runEnv(t, env{cwd: dir}, "doctor", "--profile", "web")
	if !strings.Contains(out, "policy: ") || !strings.Contains(out, "profile web") {
		t.Errorf("human output: %q", out)
	}
}

// doctor --fix repairs a policy others may write: with --yes without
// asking, on a terminal after a yes.
func TestDoctorFixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes")
	}
	dir := t.TempDir()
	if code, _, errs := runEnv(t, env{cwd: dir}, "profile", "add", "--non-interactive"); code != exitOK {
		t.Fatal(errs)
	}
	path := projectConfig(dir)
	loosen := func() {
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	loosen()
	_, d := doctorJSON(t, env{cwd: dir})
	if c, _ := findCheck(d, "permissions"); c.Status != verbs.StatusFail || d.OK {
		t.Fatalf("loose mode: %+v", d)
	}
	// On a terminal, a no repairs nothing.
	_, d = doctorJSON(t, env{cwd: dir, tty: true, stdin: strings.NewReader("n\n")}, "--fix")
	if len(d.Fixed) != 0 {
		t.Fatalf("repaired after a no: %+v", d)
	}
	_, d = doctorJSON(t, env{cwd: dir, tty: true, stdin: strings.NewReader("y\n")}, "--fix")
	if len(d.Fixed) != 1 {
		t.Fatalf("not repaired after a yes: %+v", d)
	}
	loosen()
	_, d = doctorJSON(t, env{cwd: dir}, "--fix", "--yes")
	if c, _ := findCheck(d, "permissions"); len(d.Fixed) != 1 || !strings.Contains(d.Fixed[0], "chmod go-w") || c.Status != verbs.StatusOK {
		t.Fatalf("--fix --yes: %+v", d)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}
