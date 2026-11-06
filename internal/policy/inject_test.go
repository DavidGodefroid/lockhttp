package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

const injectConf = `
[profiles.default]
[[profiles.default.internal_hosts]]
host  = "homeassistant"
ports = [8123]
read  = true

[[profiles.default.inject]]
id     = "ha"
host   = "HomeAssistant"
port   = 8123
header = "authorization"
scheme = "Bearer"
credential = "ha-token"
note   = "Home Assistant long-lived token"

[[profiles.default.inject]]
id        = "api-dev"
container = "lea-dev"
host      = "api.example.com"
port      = 443
header    = "X-Api-Key"
credential = "example-key"
`

func TestInjectParse(t *testing.T) {
	p, err := Parse([]byte(injectConf), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Inject) != 2 || p.Inject[0].ID != "api-dev" || p.Inject[1].ID != "ha" {
		t.Fatalf("inject not canonical: %+v", p.Inject)
	}
	ha := p.Inject[1]
	if ha.Host != "homeassistant" || ha.Header != "Authorization" || ha.Scheme != "Bearer" || ha.Credential != "ha-token" || ha.Port != 8123 {
		t.Fatalf("ha: %+v", ha)
	}
	if got := p.InjectFor("any", "homeassistant", 8123); len(got) != 1 || got[0].ID != "ha" {
		t.Fatalf("InjectFor ha: %+v", got)
	}
	if got := p.InjectFor("any", "homeassistant", 80); len(got) != 0 {
		t.Fatalf("another port: %+v", got)
	}
	if got := p.InjectFor("lea-other", "api.example.com", 443); len(got) != 0 {
		t.Fatalf("another container: %+v", got)
	}
	if got := p.InjectFor("lea-dev", "api.example.com", 443); len(got) != 1 {
		t.Fatalf("its container: %+v", got)
	}
	// The policy, and so the hub's view of it, names the secret only.
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"credential":"ha-token"`) {
		t.Fatalf("json: %s", b)
	}
	// The JSON round trip the console and the gate do keeps the
	// fingerprint.
	var q Policy
	if err := json.Unmarshal(b, &q); err != nil {
		t.Fatal(err)
	}
	if Canonical(q).Fingerprint() != p.Fingerprint() {
		t.Fatal("fingerprint changed through JSON")
	}
	if c := p.Clone(); len(c.Inject) != 2 {
		t.Fatal("clone lost inject")
	}
}

func TestInjectScopedWins(t *testing.T) {
	conf := `
[profiles.default]
[[profiles.default.inject]]
id = "all"
host = "api.example.com"
port = 443
header = "Authorization"
credential = "shared"
[[profiles.default.inject]]
id = "mine"
container = "lea-dev"
host = "api.example.com"
port = 443
header = "Authorization"
credential = "mine"
`
	p, err := Parse([]byte(conf), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.InjectFor("lea-dev", "api.example.com", 443); len(got) != 1 || got[0].ID != "mine" {
		t.Fatalf("scoped: %+v", got)
	}
	if got := p.InjectFor("lea-x", "api.example.com", 443); len(got) != 1 || got[0].ID != "all" {
		t.Fatalf("all: %+v", got)
	}
	// InjectAt sees both, whatever the container.
	if got := p.InjectAt("API.example.com", 443); len(got) != 2 {
		t.Fatalf("InjectAt: %+v", got)
	}
	if got := p.InjectAt("api.example.com", 80); len(got) != 0 {
		t.Fatalf("InjectAt other port: %+v", got)
	}
}

// A policy without injection keeps the fingerprint it had before
// injection existed: no "inject" key in its JSON.
func TestInjectAbsentKeepsJSON(t *testing.T) {
	p, err := Parse([]byte("[profiles.default]\n"), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "inject") {
		t.Fatalf("empty inject in JSON: %s", b)
	}
}

func TestInjectRefuses(t *testing.T) {
	base := "[profiles.default]\nsplice = [\"pinned.example.com\"]\n[[profiles.default.inject]]\n"
	for name, body := range map[string]string{
		"pattern host":   `id="a"` + "\n" + `host="*.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"",
		"ip host":        `id="a"` + "\n" + `host="10.0.5.55"` + "\nport=8123\nheader=\"Authorization\"\ncredential=\"s\"",
		"no port":        `id="a"` + "\n" + `host="api.example.com"` + "\nheader=\"Authorization\"\ncredential=\"s\"",
		"bad port":       `id="a"` + "\n" + `host="api.example.com"` + "\nport=70000\nheader=\"Authorization\"\ncredential=\"s\"",
		"host header":    `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Host\"\ncredential=\"s\"",
		"proxy header":   `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Proxy-Authorization\"\ncredential=\"s\"",
		"length header":  `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"content-length\"\ncredential=\"s\"",
		"bad header":     `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"X Api\"\ncredential=\"s\"",
		"no credential":  `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"",
		"secret value":   `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"ghp_" + strings.Repeat("a1B2", 9) + "\"",
		"bad scheme":     `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\nscheme=\"Bearer x\"\ncredential=\"s\"",
		"spliced host":   `id="a"` + "\n" + `host="pinned.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"",
		"unknown key":    `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"\nvalue=\"x\"",
		"bad id":         `id="-a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"",
		"bad container":  `id="a"` + "\ncontainer=\"a b\"\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"",
		"duplicate id":   `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"\n[[profiles.default.inject]]\nid=\"a\"\nhost=\"b.example.com\"\nport=443\nheader=\"Authorization\"\ncredential=\"s\"",
		"duplicate same": `id="a"` + "\n" + `host="api.example.com"` + "\nport=443\nheader=\"Authorization\"\ncredential=\"s\"\n[[profiles.default.inject]]\nid=\"b\"\nhost=\"api.example.com\"\nport=443\nheader=\"authorization\"\ncredential=\"t\"",
	} {
		if _, err := Parse([]byte(base+body+"\n"), "c", "default"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInjectDiff(t *testing.T) {
	none, err := Parse([]byte("[profiles.default]\n"), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	with, err := Parse([]byte(injectConf), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	added := with.Diff(none)
	n := 0
	for _, c := range added {
		if c.Field == "inject" {
			n++
			if !c.Loosens {
				t.Errorf("adding an injection must loosen: %+v", c)
			}
		}
	}
	if n != 2 {
		t.Fatalf("added: %+v", added)
	}
	for _, c := range none.Diff(with) {
		if c.Field == "inject" && c.Loosens {
			t.Errorf("removing an injection must tighten: %+v", c)
		}
	}
	// Pointing an injection at another secret loosens (an addition).
	changed, err := Parse([]byte(strings.Replace(injectConf, `credential = "ha-token"`, `credential = "other"`, 1)), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range changed.Diff(with) {
		if c.Field == "inject" && c.New != "" {
			found = found || c.Loosens
		}
	}
	if !found {
		t.Fatal("changing an injection's secret must loosen")
	}
	desc := strings.Join(with.Describe(), "\n")
	if !strings.Contains(desc, "inject ha homeassistant:8123 Authorization Bearer credential=ha-token all-containers") {
		t.Fatalf("describe:\n%s", desc)
	}
}

func TestInjectMethodsPaths(t *testing.T) {
	conf := strings.Replace(injectConf, `note   = "Home Assistant long-lived token"`, `methods = ["post", "GET"]
paths = ["/api/*", "/health"]`, 1)
	p, err := Parse([]byte(conf), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	ha := p.Inject[1]
	if strings.Join(ha.Methods, ",") != "GET,POST" || strings.Join(ha.Paths, ",") != "/api/*,/health" {
		t.Fatalf("ha: %+v", ha)
	}
	if !strings.Contains(ha.String(), "methods=GET,POST paths=/api/*,/health") {
		t.Fatalf("String: %s", ha.String())
	}
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/api/states", true}, {"POST", "/health", true}, {"GET", "/healthz", false},
		{"DELETE", "/api/states", false}, {"GET", "/admin", false}, {"TRACE", "/api/x", false},
	} {
		if got := len(p.InjectForRequest("x", "homeassistant", 8123, tc.method, tc.path)) == 1; got != tc.want {
			t.Errorf("%s %s: %v", tc.method, tc.path, got)
		}
	}
	// Without methods, TRACE and TRACK still never get the credential.
	if got := p.InjectForRequest("lea-dev", "api.example.com", 443, "TRACE", "/"); len(got) != 0 {
		t.Fatalf("TRACE: %+v", got)
	}
	if got := p.InjectForRequest("lea-dev", "api.example.com", 443, "PUT", "/x"); len(got) != 1 {
		t.Fatalf("PUT: %+v", got)
	}
	// A clone does not share the lists.
	q := p.Clone()
	q.Inject[1].Methods[0] = "X"
	if p.Inject[1].Methods[0] != "GET" {
		t.Fatal("Clone shares the methods")
	}
	for name, bad := range map[string]string{
		"trace":    `methods = ["TRACE"]`,
		"track":    `methods = ["track"]`,
		"bad path": `paths = ["api"]`,
		"method":   `methods = ["G ET"]`,
	} {
		c := strings.Replace(injectConf, `note   = "Home Assistant long-lived token"`, bad, 1)
		if _, err := Parse([]byte(c), "c", "default"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
