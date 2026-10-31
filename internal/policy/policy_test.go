package policy

import (
	"strings"
	"testing"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

const sample = `
[profiles.default]
mode = "enforce"
heuristics = "shadow"
buffer_limit = "10MiB"
trusted = ["go.dev", "*.python.org", "GO.dev"]
splice = ["pinned.example.com"]

[[profiles.default.internal_hosts]]
host = "ci.internal"
ports = [8080]
read = true

[[profiles.default.rules]]
id = "github-api-read"
host = "api.github.com"
methods = ["get", "HEAD"]
verdict = "free"

[[profiles.default.rules]]
id = "npm-audit"
container = "lea-ab12cd34ef"
host = "registry.npmjs.org"
methods = ["POST"]
path = "/-/npm/v1/security/advisories/bulk"
verdict = "auto"
max_body = "256KiB"
expires = "2026-12-31"
`

func mustParse(t *testing.T, src, profile string) Policy {
	t.Helper()
	p, err := Parse([]byte(src), "config.toml", profile)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestParseCanonical(t *testing.T) {
	p := mustParse(t, sample, "default")
	if p.Name != "default" || p.Mode != ModeEnforce || p.Heuristics != ModeShadow {
		t.Fatalf("modes: %+v", p)
	}
	if p.BufferLimit != 10<<20 {
		t.Fatalf("buffer_limit %d", p.BufferLimit)
	}
	if strings.Join(p.Trusted, ",") != "*.python.org,go.dev" {
		t.Fatalf("trusted not canonical: %v", p.Trusted)
	}
	if p.Hold != 60 || p.ConnectGrant != 600 {
		t.Fatalf("defaults: hold %d grant %d", p.Hold, p.ConnectGrant)
	}
	if len(p.Rules) != 2 || p.Rules[0].ID != "github-api-read" {
		t.Fatalf("rules not sorted: %+v", p.Rules)
	}
	if strings.Join(p.Rules[0].Methods, ",") != "GET,HEAD" {
		t.Fatalf("methods not canonical: %v", p.Rules[0].Methods)
	}
	r := p.Rules[1]
	if r.Verdict != VerdictAuto || r.MaxBody != 256<<10 || r.Expires != "2026-12-31" || r.Container != "lea-ab12cd34ef" {
		t.Fatalf("rule: %+v", r)
	}
	if len(p.Internal) != 1 || !p.Internal[0].Read || p.Internal[0].Ports[0] != 8080 {
		t.Fatalf("internal: %+v", p.Internal)
	}
	if p.Profile().Credentials != "none" || p.Profile().Name != "default" {
		t.Fatalf("profile: %+v", p.Profile())
	}
}

func TestFingerprintStable(t *testing.T) {
	a := mustParse(t, sample, "default")
	reordered := strings.Replace(sample, `["go.dev", "*.python.org", "GO.dev"]`, `["*.python.org", "go.dev"]`, 1)
	b := mustParse(t, reordered, "default")
	if kconfig.Fingerprint(a) != kconfig.Fingerprint(b) {
		t.Fatal("fingerprint depends on list order")
	}
}

func TestParseRefuses(t *testing.T) {
	cases := map[string]string{
		"unknown profile":    "[profiles.other]\n",
		"bad mode":           "[profiles.default]\nmode = \"loose\"\n",
		"bad verdict":        "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nverdict = \"maybe\"\n",
		"no host":            "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nverdict = \"free\"\n",
		"dup id":             "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nverdict = \"ask\"\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"b.com\"\nverdict = \"ask\"\n",
		"agent scope":        "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nagent = \"dev-5\"\nverdict = \"auto\"\n",
		"secret key":         "[profiles.default]\napi_token = \"x\"\n",
		"ip literal host":    "[profiles.default]\ntrusted = [\"10.0.0.1\"]\n",
		"wildcard tld":       "[profiles.default]\ntrusted = [\"*.com\"]\n",
		"auto on spliced":    "[profiles.default]\nsplice = [\"a.com\"]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nverdict = \"auto\"\n",
		"auto on receive":    "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"github.com\"\npath = \"/o/r.git/git-receive-pack\"\nverdict = \"auto\"\n",
		"auto on messaging":  "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"hooks.slack.com\"\nverdict = \"auto\"\n",
		"auto on publish":    "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"registry.npmjs.org\"\nmethods = [\"PUT\"]\nverdict = \"auto\"\n",
		"auto on production": "[profiles.default]\nproduction = true\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nmethods = [\"POST\"]\nverdict = \"auto\"\n",
		"auto on all hosts":  "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"*\"\nverdict = \"auto\"\n",
		"bad expires":        "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nverdict = \"ask\"\nexpires = \"soon\"\n",
		"bad method":         "[profiles.default]\n[[profiles.default.rules]]\nid = \"x\"\nhost = \"a.com\"\nmethods = [\"G ET\"]\nverdict = \"ask\"\n",
		"control char":       "[profiles.default]\ntrusted = [\"a\u202e.com\"]\n",
		"internal no ports":  "[profiles.default]\n[[profiles.default.internal_hosts]]\nhost = \"ci.internal\"\n",
		"bad heuristics":     "[profiles.default]\nheuristics = \"loud\"\n",
		"bad buffer":         "[profiles.default]\nbuffer_limit = \"lots\"\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src), "config.toml", "default"); err == nil {
				t.Fatalf("accepted:\n%s", src)
			}
		})
	}
}

func loosened(changes []kconfig.Change) []string {
	var out []string
	for _, c := range changes {
		if c.Loosens {
			out = append(out, c.Field)
		}
	}
	return out
}

func TestDiff(t *testing.T) {
	base := mustParse(t, sample, "default")
	cases := []struct {
		name    string
		edit    func(*Policy)
		loosens bool
	}{
		{"same", func(*Policy) {}, false},
		{"add trusted", func(p *Policy) { p.Trusted = append(p.Trusted, "zz.example.com") }, true},
		{"remove trusted", func(p *Policy) { p.Trusted = p.Trusted[1:] }, false},
		{"add splice", func(p *Policy) { p.Splice = append(p.Splice, "zz.com") }, true},
		{"add deny", func(p *Policy) { p.Deny = append(p.Deny, "zz.com") }, false},
		{"shadow mode", func(p *Policy) { p.Mode = ModeShadow }, true},
		{"heuristics off", func(p *Policy) { p.Heuristics = ModeOff }, true},
		{"heuristics enforce", func(p *Policy) { p.Heuristics = ModeEnforce }, false},
		{"bigger buffer", func(p *Policy) { p.BufferLimit *= 2 }, true},
		{"longer grant", func(p *Policy) { p.ConnectGrant *= 2 }, true},
		{"shorter grant", func(p *Policy) { p.ConnectGrant /= 2 }, false},
		{"not production", func(p *Policy) { p.Production = true }, false},
		{"internal read", func(p *Policy) { p.Internal[0].Ports = append(p.Internal[0].Ports, 9090) }, true},
		{"new rule", func(p *Policy) { p.Rules = append(p.Rules, Rule{ID: "zz", Host: "a.com", Verdict: VerdictFree}) }, true},
		{"new deny rule", func(p *Policy) { p.Rules = append(p.Rules, Rule{ID: "zz", Host: "a.com", Verdict: VerdictDeny}) }, false},
		{"rule ask to free", func(p *Policy) { p.Rules[1].Verdict = VerdictFree }, true},
		{"rule free to ask", func(p *Policy) { p.Rules[0].Verdict = VerdictAsk }, false},
		{"rule drops container", func(p *Policy) { p.Rules[1].Container = "" }, true},
		{"rule adds method", func(p *Policy) { p.Rules[0].Methods = []string{"GET", "HEAD", "POST"} }, true},
		{"rule drops method", func(p *Policy) { p.Rules[0].Methods = []string{"GET"} }, false},
		{"rule wider path", func(p *Policy) { p.Rules[1].Path = "/-/*" }, true},
		{"rule longer expiry", func(p *Policy) { p.Rules[1].Expires = "2027-12-31" }, true},
		{"rule no expiry", func(p *Policy) { p.Rules[1].Expires = "" }, true},
		{"rule bigger body", func(p *Policy) { p.Rules[1].MaxBody = 0 }, true},
		{"rule other host", func(p *Policy) { p.Rules[0].Host = "api.gitlab.com" }, true},
		{"remove free rule", func(p *Policy) { p.Rules = p.Rules[1:] }, false},
		{"remove auto rule", func(p *Policy) { p.Rules = p.Rules[:1] }, true},
		{"narrow auto rule", func(p *Policy) { p.Rules[1].Container = "lea-other" }, true},
		{"narrow free rule", func(p *Policy) { p.Rules[0].Methods = []string{"GET"} }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cur := base.Clone()
			c.edit(&cur)
			cur = Canonical(cur)
			got := loosened(cur.Diff(base))
			if (len(got) > 0) != c.loosens {
				t.Fatalf("loosens=%v, got %v (all: %+v)", c.loosens, got, cur.Diff(base))
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	p := mustParse(t, sample, "default")
	text := strings.Join(p.Describe(), "\n")
	for _, want := range []string{"enforce", "github-api-read", "auto", "lea-ab12cd34ef", "*.python.org"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Describe lacks %q:\n%s", want, text)
		}
	}
}

func TestRuleActive(t *testing.T) {
	r := Rule{ID: "x", Host: "a.com", Verdict: VerdictFree, Expires: "2026-10-28"}
	if !r.Active(time.Date(2026, 10, 28, 23, 0, 0, 0, time.UTC)) {
		t.Fatal("expires is inclusive")
	}
	if r.Active(time.Date(2026, 10, 29, 0, 0, 1, 0, time.UTC)) {
		t.Fatal("expired rule active")
	}
}

func TestHostMatch(t *testing.T) {
	cases := []struct {
		pat, host string
		ok        bool
	}{
		{"go.dev", "go.dev", true},
		{"go.dev", "pkg.go.dev", false},
		{"*.python.org", "docs.python.org", true},
		{"*.python.org", "python.org", false},
		{"*.python.org", "a.b.python.org", true},
		{"*", "anything.io", true},
		{"go.dev", "GO.DEV.", true},
	}
	for _, c := range cases {
		if got := HostMatch(c.pat, c.host); got != c.ok {
			t.Errorf("HostMatch(%q,%q)=%v", c.pat, c.host, got)
		}
	}
}

func TestDefaultParses(t *testing.T) {
	p, err := Parse([]byte(DefaultConfig(nil)), "config.toml", "default")
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if len(p.Trusted) == 0 {
		t.Fatal("default config trusts nothing")
	}
	q, err := Parse([]byte(DefaultConfig([]string{"example.org", ".corp.example"})), "config.toml", "default")
	if err != nil {
		t.Fatalf("default config with imports: %v", err)
	}
	if !q.Trusts("example.org") || !q.Trusts("x.corp.example") {
		t.Fatalf("imports not trusted: %v", q.Trusted)
	}
}

// Canaries: a pasted token, and a URL carrying one in its userinfo.
const (
	canary    = "glsa_CanarySecretToken123"
	canaryURL = "https://user:glsa_Canary@h"
)

// An error names the key (or the entry's place in the file) and never
// repeats the value given: a value may be a pasted secret.
func TestErrorsDoNotEchoValues(t *testing.T) {
	const prof = "[profiles.default]\n"
	rule := func(fields string) string {
		return prof + "[[profiles.default.rules]]\n" + fields
	}
	ih := func(fields string) string {
		return prof + "[[profiles.default.internal_hosts]]\n" + fields
	}
	// The URL canary trips lockkit's embedded-password check first for most
	// keys; the token canary reaches lockhttp's own messages.
	cases := []struct {
		name, src, key string
	}{
		{"mode", prof + `mode = "C"`, "mode"},
		{"heuristics", prof + `heuristics = "C"`, "heuristics"},
		{"buffer_limit", prof + `buffer_limit = "C"`, "buffer_limit"},
		{"hold", prof + `hold = "C"`, "hold"},
		{"connect_grant", prof + `connect_grant = "C"`, "connect_grant"},
		{"idle_timeout", prof + `idle_timeout = "C"`, "idle_timeout"},
		{"max_session", prof + `max_session = "C"`, "max_session"},
		{"trusted", prof + `trusted = ["go.dev", "C"]`, "trusted entry 2"},
		{"trusted single label", prof + `trusted = ["glsa-canarysecrettoken123"]`, "trusted entry 1"},
		{"trusted ip literal", prof + `trusted = ["fe80::1%C"]`, "trusted entry 1"},
		{"splice", prof + `splice = ["C"]`, "splice entry 1"},
		{"deny", prof + `deny = ["C"]`, "deny entry 1"},
		{"redirect_cdn no >", prof + `redirect_cdn = ["C"]`, "redirect_cdn entry 1"},
		{"redirect_cdn origin", prof + `redirect_cdn = ["C>cdn.example.com"]`, "redirect_cdn entry 1 origin"},
		{"redirect_cdn cdn", prof + `redirect_cdn = ["a.example.com>C"]`, "redirect_cdn entry 1 cdn"},
		{"internal host", ih("host = \"C\"\nports = [443]"), "internal_hosts entry 1 host"},
		{"internal pattern", ih("host = \"*.glsa-canarysecrettoken123.example\"\nports = [443]"), "internal_hosts entry 1"},
		{"internal no ports", ih(`host = "glsa-canarysecrettoken123"`), "internal_hosts entry 1"},
		{"internal bad port", ih("host = \"glsa-canarysecrettoken123\"\nports = [70000]"), "internal_hosts entry 1"},
		// The token alone is a valid id or container: only the URL fails.
		{"rule id", rule("id = \"C\"\nhost = \"a.com\"\nverdict = \"ask\""), "rules entry 1"},
		{"rule id, other error", rule("id = \"glsa_CanarySecretToken123\"\nhost = \"a.com\"\nverdict = \"C\""), "rules entry 1"},
		{"rule id twice", rule("id = \"glsa_CanarySecretToken123\"\nhost = \"a.com\"\nverdict = \"ask\"\n") +
			"[[profiles.default.rules]]\nid = \"glsa_CanarySecretToken123\"\nhost = \"b.com\"\nverdict = \"ask\"", "rules entry 2"},
		{"rule agent", rule("id = \"glsa_CanarySecretToken123\"\nhost = \"a.com\"\nagent = \"C\"\nverdict = \"ask\""), "rules entry 1"},
		{"rule container", rule("id = \"x\"\ncontainer = \"C\"\nhost = \"a.com\"\nverdict = \"ask\""), "rules entry 1"},
		{"rule host", rule("id = \"x\"\nhost = \"C\"\nverdict = \"ask\""), "rules entry 1 host"},
		{"rule verdict", rule("id = \"x\"\nhost = \"a.com\"\nverdict = \"C\""), "rules entry 1"},
		{"rule method", rule("id = \"x\"\nhost = \"a.com\"\nmethods = [\"C\"]\nverdict = \"ask\""), "rules entry 1"},
		{"rule path", rule("id = \"x\"\nhost = \"a.com\"\npath = \"C\"\nverdict = \"ask\""), "rules entry 1"},
		{"rule path control", rule("id = \"x\"\nhost = \"a.com\"\npath = \"/C\u202e\"\nverdict = \"ask\""), "rules entry 1 path"},
		{"rule note control", rule("id = \"x\"\nhost = \"a.com\"\nnote = \"C\u202e\"\nverdict = \"ask\""), "rules entry 1 note"},
		{"rule expires", rule("id = \"x\"\nhost = \"a.com\"\nexpires = \"C\"\nverdict = \"ask\""), "rules entry 1"},
		{"rule max_body", rule("id = \"x\"\nhost = \"a.com\"\nmax_body = \"C\"\nverdict = \"ask\""), "rules entry 1: max_body"},
		{"rule auto forbidden", rule("id = \"glsa_CanarySecretToken123\"\nhost = \"*\"\nverdict = \"auto\""), "rules entry 1"},
		// lockkit's decoder: the key, not the value.
		{"ports type", ih("host = \"ci\"\nports = [\"C\"]"), "internal_hosts.ports"},
	}
	for _, c := range cases {
		for _, secret := range []string{canary, canaryURL} {
			t.Run(c.name+"/"+secret, func(t *testing.T) {
				src := strings.ReplaceAll(c.src, `"C`, `"`+secret)
				_, err := Parse([]byte(src+"\n"), "config.toml", "default")
				if err == nil && secret == canary && (c.name == "rule id" || c.name == "rule container") {
					return
				}
				if err == nil {
					t.Fatalf("accepted:\n%s", src)
				}
				msg := err.Error()
				for _, leak := range []string{canary, "glsa_Canary", "glsa-canarysecrettoken123", "user:"} {
					if strings.Contains(msg, leak) {
						t.Fatalf("the error repeats the value (%s): %s", leak, msg)
					}
				}
				if !strings.Contains(msg, c.key) {
					t.Fatalf("the error does not name %q: %s", c.key, msg)
				}
			})
		}
	}
}

// CheckHostPattern (the signer checks the hosts it signs with it) names
// the key, not the host.
func TestCheckHostPatternDoesNotEcho(t *testing.T) {
	for _, h := range []string{canary, canaryURL, "glsa-canarysecrettoken123", "fe80::1%" + canary, "*.glsa-canarysecrettoken123"} {
		_, err := CheckHostPattern("host", h, false)
		if err == nil || strings.Contains(err.Error(), "anary") || (!strings.HasPrefix(err.Error(), "host ") && !strings.HasPrefix(err.Error(), "host: ")) {
			t.Errorf("%s: %v", h, err)
		}
	}
}

// A missing profile: --profile is a value given on the command line.
func TestNoProfileDoesNotEcho(t *testing.T) {
	_, err := Parse([]byte("[profiles.default]\n"), "config.toml", canary)
	if err == nil || strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), "--profile") {
		t.Fatalf("%v", err)
	}
}
