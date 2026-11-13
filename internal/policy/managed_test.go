package policy

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

// managedFile parses a managed file's text (its ownership and signature
// are Load's, not this package's).
func managedFile(t *testing.T, text string) *managed.File {
	t.Helper()
	m, err := managed.Parse([]byte("version = 1\norganisation = \"Example Corp\"\n" + text))
	if err != nil {
		t.Fatalf("managed.Parse: %v", err)
	}
	return m
}

func mustManaged(t *testing.T, text string) *Managed {
	t.Helper()
	mg, err := LoadManaged(managedFile(t, text))
	if err != nil {
		t.Fatalf("LoadManaged: %v", err)
	}
	return mg
}

func managedErr(t *testing.T, text string) string {
	t.Helper()
	_, err := LoadManaged(managedFile(t, text))
	if err == nil {
		t.Fatalf("LoadManaged accepted:\n%s", text)
	}
	return err.Error()
}

func TestNoManagedFileChangesNothing(t *testing.T) {
	mg, err := LoadManaged(nil)
	if mg != nil || err != nil {
		t.Fatalf("LoadManaged(nil) = %v, %v", mg, err)
	}
	plain := mustParse(t, sample, "default")
	p, err := ParseManaged([]byte(sample), "config.toml", "default", nil)
	if err != nil || p.Fingerprint() != plain.Fingerprint() {
		t.Fatalf("ParseManaged(nil) differs: %v", err)
	}
	// A managed file without a [lockhttp] section bounds nothing and keeps
	// the fingerprint: a policy approved before it stays approved.
	mg = mustManaged(t, "[locksql.bounds]\ntier = \"read\"\n")
	if mg.Bounded() {
		t.Fatal("a file without [lockhttp] bounds lockhttp")
	}
	p, err = ParseManaged([]byte(sample), "config.toml", "default", mg)
	if err != nil || p.Fingerprint() != plain.Fingerprint() {
		t.Fatalf("an unrelated managed file changes the policy: %v", err)
	}
	if mg.ManagedBounds(p).Ceiling != nil {
		t.Fatal("an unrelated managed file has a ceiling")
	}
}

func TestFamilyVaultHasNoEffect(t *testing.T) {
	mg := mustManaged(t, "[family]\nvault = { address = \"https://vault.example.com\", required = true }\n")
	if mg.Bounded() {
		t.Fatal("[family] vault bounds lockhttp, which has no credentials")
	}
	if _, err := ParseManaged([]byte(sample), "config.toml", "default", mg); err != nil {
		t.Fatal(err)
	}
}

func TestManagedProfileServedAsWritten(t *testing.T) {
	mg := mustManaged(t, `
[lockhttp.profiles.corp]
mode = "enforce"
heuristics = "enforce"
trusted = ["*.example.com"]
`)
	if got := strings.Join(mg.ProfileNames(), ","); got != "corp" {
		t.Fatalf("ProfileNames = %q", got)
	}
	p, err := ParseManaged([]byte(sample), "config.toml", "corp", mg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "corp" || p.Heuristics != ModeEnforce || strings.Join(p.Trusted, ",") != "*.example.com" || p.Hold != DefaultHold {
		t.Fatalf("managed profile: %+v", p)
	}
	names, err := ProfilesManaged([]byte(sample), "config.toml", mg)
	if err != nil || strings.Join(names, ",") != "corp,default" {
		t.Fatalf("ProfilesManaged = %v, %v", names, err)
	}
	// A file profile of a managed name is refused, naming it.
	_, err = ParseManaged([]byte(sample+"\n[profiles.corp]\n"), "config.toml", "default", mg)
	if err == nil || !strings.Contains(err.Error(), `profile "corp"`) || !strings.Contains(err.Error(), "managed configuration") {
		t.Fatalf("redefined managed profile: %v", err)
	}
}

func TestManagedProfileBeyondBoundsRefused(t *testing.T) {
	msg := managedErr(t, `
[lockhttp.bounds]
mode = "enforce"
[lockhttp.profiles.corp]
mode = "shadow"
`)
	if !strings.Contains(msg, "lockhttp.profiles.corp") || !strings.Contains(msg, "lockhttp.bounds.mode = enforce") {
		t.Fatalf("error: %s", msg)
	}
}

func TestManagedDefaults(t *testing.T) {
	mg := mustManaged(t, `
[lockhttp.bounds]
connect_grant = "10m"
[lockhttp.defaults]
heuristics = "enforce"
connect_grant = "5m"
hold = "30s"
`)
	// Applied where the profile leaves the key unset.
	p, err := ParseManaged([]byte("[profiles.default]\n"), "c", "default", mg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Heuristics != ModeEnforce || p.ConnectGrant != 300 || p.Hold != 30 {
		t.Fatalf("defaults not applied: %+v", p)
	}
	// A file value within the bounds wins over the default.
	p, err = ParseManaged([]byte("[profiles.default]\nheuristics = \"shadow\"\nconnect_grant = \"8m\"\n"), "c", "default", mg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Heuristics != ModeShadow || p.ConnectGrant != 480 || p.Hold != 30 {
		t.Fatalf("file values lost: %+v", p)
	}
	if vs := mg.Check(p); len(vs) != 0 {
		t.Fatalf("within bounds, violations %v", vs)
	}
	// A production default, and the file's explicit false over it.
	mg = mustManaged(t, "[lockhttp.defaults]\nproduction = true\n")
	if p, err = ParseManaged([]byte("[profiles.prod-eu]\n"), "c", "prod-eu", mg); err != nil || !p.Production {
		t.Fatalf("production default: %+v %v", p, err)
	}
	if p, err = ParseManaged([]byte("[profiles.prod-eu]\nproduction = false\n"), "c", "prod-eu", mg); err != nil || p.Production {
		t.Fatalf("production false in the file: %+v %v", p, err)
	}
}

func TestManagedDefaultBeyondBoundsRefused(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"[lockhttp.bounds]\nconnect_grant = \"10m\"\n[lockhttp.defaults]\nconnect_grant = \"1h\"\n", "lockhttp.bounds.connect_grant = 600s"},
		{"[lockhttp.bounds]\nmode = \"enforce\"\n[lockhttp.defaults]\nmode = \"shadow\"\n", "lockhttp.bounds.mode = enforce"},
		{"[lockhttp.bounds]\nproduction = true\n[lockhttp.defaults]\nproduction = false\n", "lockhttp.bounds.production = true"},
		{"[lockhttp.bounds]\nbuffer_limit = \"1MiB\"\n[lockhttp.defaults]\nbuffer_limit = \"2MiB\"\n", "lockhttp.bounds.buffer_limit = 1MiB"},
		{"[lockhttp.defaults]\nmode = \"loose\"\n", "mode must be"},
	} {
		if msg := managedErr(t, tc.text); !strings.Contains(msg, "lockhttp.defaults") || !strings.Contains(msg, tc.want) {
			t.Errorf("%q: error %s", tc.text, msg)
		}
	}
}

func TestManagedBoundsRefusedKeys(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"[lockhttp.bounds]\nhold = \"30s\"\n", `unknown key "hold"`},
		{"[lockhttp.bounds]\ninject = []\n", `unknown key "inject"`},
		{"[lockhttp.bounds]\nmode = \"shadow\"\n", "mode: the only bound"},
		{"[lockhttp.bounds]\nproduction = false\n", "production: the only bound"},
		{"[lockhttp.bounds]\nheuristics = \"off\"\n", "heuristics: must be"},
		{"[lockhttp.bounds]\ntrusted = [\"1.2.3.4\"]\n", "trusted entry 1"},
		{"[[lockhttp.bounds.rules]]\nid = \"x\"\nhost = \"example.com\"\nverdict = \"auto\"\n", "verdict must be deny or ask"},
		{"[[lockhttp.bounds.rules]]\nid = \"x\"\nhost = \"example.com\"\nverdict = \"free\"\n", "verdict must be deny or ask"},
		{"[[lockhttp.bounds.rules]]\nid = \"x\"\nhost = \"a.example.com\"\nverdict = \"deny\"\n[[lockhttp.bounds.rules]]\nid = \"x\"\nhost = \"b.example.com\"\nverdict = \"ask\"\n", "already used"},
	} {
		if msg := managedErr(t, tc.text); !strings.Contains(msg, tc.want) {
			t.Errorf("%q: error %s", tc.text, msg)
		}
	}
}

const boundsText = `
[lockhttp.bounds]
production = true
mode = "enforce"
heuristics = "enforce"
buffer_limit = "1MiB"
connect_grant = "5m"
idle_timeout = "1h"
max_session = "8h"
trusted = ["*.example.com", "go.dev"]
splice = ["pinned.example.com"]
redirect_cdn = ["*.example.com>cdn.example.net"]
internal_hosts = [{ host = "ci.internal", ports = [8080], read = false }]
deny = ["paste.example.org"]
`

func TestBoundsViolationPerFamily(t *testing.T) {
	mg := mustManaged(t, boundsText)
	p := mustParse(t, `
[profiles.dev]
mode = "shadow"
heuristics = "shadow"
buffer_limit = "4MiB"
connect_grant = "10m"
idle_timeout = "2h"
max_session = "24h"
trusted = ["api.example.com", "evil.example.org"]
splice = ["other.example.org"]
redirect_cdn = ["api.example.com>cdn.example.org"]
internal_hosts = [{ host = "ci.internal", ports = [8080, 9090], read = true }]
`, "dev")
	got := map[string]string{}
	for _, v := range mg.Check(p) {
		got[v.Key+" "+v.Field+" "+v.Value] = v.String()
	}
	for _, want := range []string{
		"blocked by company policy: lockhttp.bounds.production = true (profile dev: production = false)",
		"blocked by company policy: lockhttp.bounds.mode = enforce (profile dev: mode = shadow)",
		"blocked by company policy: lockhttp.bounds.heuristics = enforce (profile dev: heuristics = shadow)",
		"blocked by company policy: lockhttp.bounds.buffer_limit = 1MiB (profile dev: buffer_limit = 4MiB)",
		"blocked by company policy: lockhttp.bounds.connect_grant = 300s (profile dev: connect_grant = 600s)",
		"blocked by company policy: lockhttp.bounds.idle_timeout = 3600s (profile dev: idle_timeout = 7200s)",
		"blocked by company policy: lockhttp.bounds.max_session = 28800s (profile dev: max_session = 86400s)",
		"blocked by company policy: lockhttp.bounds.trusted does not allow evil.example.org (profile dev: trusted + evil.example.org)",
		"blocked by company policy: lockhttp.bounds.splice does not allow other.example.org (profile dev: splice + other.example.org)",
		"blocked by company policy: lockhttp.bounds.redirect_cdn does not allow api.example.com>cdn.example.org (profile dev: redirect_cdn + api.example.com>cdn.example.org)",
		"blocked by company policy: lockhttp.bounds.internal_hosts does not allow ci.internal:9090 ask (profile dev: internal_hosts + ci.internal:9090 ask)",
		"blocked by company policy: lockhttp.bounds.internal_hosts does not allow ci.internal:8080 read (profile dev: internal_hosts + ci.internal:8080 read)",
		"blocked by company policy: lockhttp.bounds.deny requires paste.example.org (profile dev: deny - paste.example.org)",
	} {
		found := false
		for _, line := range got {
			if line == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing violation %q", want)
		}
	}
	for _, line := range got {
		if strings.Contains(line, "api.example.com (") {
			t.Errorf("an entry within the bounds is a violation: %s", line)
		}
	}
}

func TestWithinBoundsNoViolation(t *testing.T) {
	mg := mustManaged(t, boundsText)
	p := mustParse(t, `
[profiles.prod-strict]
production = true
mode = "enforce"
heuristics = "enforce"
buffer_limit = "512KiB"
connect_grant = "5m"
idle_timeout = "30m"
max_session = "8h"
trusted = ["api.example.com", "go.dev"]
splice = []
redirect_cdn = ["api.example.com>cdn.example.net"]
internal_hosts = [{ host = "ci.internal", ports = [8080] }]
deny = ["paste.example.org", "more.example.org"]
`, "prod-strict")
	if vs := mg.Check(p); len(vs) != 0 {
		t.Fatalf("violations of a stricter profile: %v", vs)
	}
}

func TestManagedRules(t *testing.T) {
	const rules = `
[[lockhttp.bounds.rules]]
id = "no-paste"
host = "*.paste.example.org"
verdict = "deny"

[[lockhttp.bounds.rules]]
id = "ask-uploads"
host = "upload.example.com"
methods = ["POST"]
verdict = "ask"
`
	mg := mustManaged(t, rules)
	p, err := ParseManaged([]byte(sample), "config.toml", "default", mg)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ManagedRules) != 2 || p.ManagedRules[0].ID != "ask-uploads" {
		t.Fatalf("managed rules: %+v", p.ManagedRules)
	}
	if p.Fingerprint() == mustParse(t, sample, "default").Fingerprint() {
		t.Fatal("the managed rules are not in the fingerprint")
	}
	if vs := mg.Check(p); len(vs) != 0 {
		t.Fatalf("violations: %v", vs)
	}
	// Removing a managed rule, or changing one in any way, loosens.
	removed := p.Clone()
	removed.ManagedRules = removed.ManagedRules[1:]
	edited := p.Clone()
	edited.ManagedRules[1].Verdict = VerdictAsk
	narrowed := p.Clone()
	narrowed.ManagedRules[0].Methods = []string{"POST", "PUT"}
	for name, q := range map[string]Policy{"removed": removed, "edited": edited, "widened": narrowed} {
		loosens := false
		for _, c := range q.Diff(p) {
			if strings.HasPrefix(c.Field, "managed rule ") && c.Loosens {
				loosens = true
			}
		}
		if !loosens {
			t.Errorf("%s managed rule: not a loosening: %v", name, q.Diff(p))
		}
	}
	// Adding one tightens.
	for _, c := range p.Diff(removed) {
		if c.Loosens {
			t.Errorf("an added managed rule loosens: %+v", c)
		}
	}
	// A policy without a managed rule the file has is beyond it, citing
	// the rules key.
	vs := mg.Check(removed)
	if len(vs) != 1 || vs[0].Key != "lockhttp.bounds.rules" {
		t.Fatalf("violations: %v", vs)
	}
}
