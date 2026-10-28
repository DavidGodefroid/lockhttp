package decide

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const cfg = `
[profiles.default]
trusted = ["go.dev", "*.python.org", "github.com", "registry.npmjs.org"]
splice = ["pinned.example.com"]
deny = ["evil.example"]

[[profiles.default.internal_hosts]]
host = "ci"
ports = [8080]
read = true

[[profiles.default.internal_hosts]]
host = "registry.corp.example"
ports = [5000]

[[profiles.default.rules]]
id = "api-gh-read"
host = "api.github.com"
methods = ["GET"]
verdict = "free"

[[profiles.default.rules]]
id = "npm-audit"
container = "lea-a"
host = "registry.npmjs.org"
methods = ["POST"]
path = "/-/npm/v1/security/advisories/bulk"
verdict = "auto"
max_body = "256KiB"

[[profiles.default.rules]]
id = "issues"
host = "api.github.com"
methods = ["POST"]
path = "/repos/o/r/issues*"
verdict = "ask"

[[profiles.default.rules]]
id = "block-gists"
host = "api.github.com"
path = "/gists*"
verdict = "deny"

[[profiles.default.rules]]
id = "old"
host = "old.example.com"
verdict = "free"
expires = "2026-01-01"

[[profiles.default.rules]]
id = "whole-host"
host = "tools.example.com"
verdict = "free"
`

func pol(t *testing.T, extra string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(strings.Replace(cfg, "[profiles.default]\n", "[profiles.default]\n"+extra, 1)), "c", "default")
	if err != nil {
		t.Fatal(err)
	}
	return &p
}

func connect(host string, port int) Request {
	return Request{Phase: PhaseConnect, Container: "lea-a", Via: "direct", Method: "CONNECT", Host: host, Port: port}
}

func get(host, path string) Request {
	return Request{Phase: PhaseHTTP, Container: "lea-a", Via: "direct", Method: "GET", Host: host, Port: 443, Path: path, Header: http.Header{}, TLS: true}
}

func post(host, path, ct string, body string) Request {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return Request{Phase: PhaseHTTP, Container: "lea-a", Via: "direct", Method: "POST", Host: host, Port: 443, Path: path,
		Header: h, Body: []byte(body), BodyLen: int64(len(body)), TLS: true}
}

func decideAll(p *policy.Policy, r Request) Decision {
	if d, stop := Floor(p, r); stop {
		return d
	}
	return Evaluate(p, r, now, NoCredentials{})
}

func TestFloor(t *testing.T) {
	p := pol(t, "")
	cases := map[string]Request{
		"ip literal":     connect("10.0.0.1", 443),
		"ipv6 literal":   connect("[::1]", 443),
		"metadata":       get("metadata.google.internal", "/"),
		"doh host":       connect("dns.google", 443),
		"doh prefix":     connect("doh.example.net", 443),
		"doh path":       get("example.org", "/dns-query"),
		"port":           connect("example.org", 22),
		"internal port":  connect("ci", 9090),
		"single label":   connect("intranet", 443),
		"sni mismatch":   func() Request { r := connect("example.org", 443); r.SNI = "evil.example"; return r }(),
		"nested connect": func() Request { r := get("example.org", "/"); r.Method = "CONNECT"; return r }(),
		"h2c":            func() Request { r := get("example.org", "/"); r.Header.Set("Upgrade", "h2c"); return r }(),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			d := decideAll(p, r)
			if d.Verdict != Deny || d.Code != product.CodeFloor {
				t.Fatalf("got %+v", d)
			}
		})
	}
	// The floor holds in shadow mode too.
	if d := decideAll(pol(t, "mode = \"shadow\"\n"), connect("10.0.0.1", 443)); d.Verdict != Deny {
		t.Fatalf("shadow lifted the floor: %+v", d)
	}
}

func TestVerdicts(t *testing.T) {
	p := pol(t, "")
	cases := []struct {
		name      string
		r         Request
		verdict   Verdict
		rule      string
		neverAuto bool
	}{
		{"trusted connect", connect("go.dev", 443), Free, "trusted", false},
		{"trusted wildcard", connect("docs.python.org", 443), Free, "trusted", false},
		{"unknown connect", connect("unknown.io", 443), Ask, "default:unknown-host", true},
		{"deny list", connect("evil.example", 443), Deny, "deny-list", false},
		{"internal read", connect("ci", 8080), Free, "internal:read", false},
		{"internal ask", connect("registry.corp.example", 5000), Ask, "internal", true},
		{"claude connect", connect("api.anthropic.com", 443), Free, "claude:host", false},
		{"other anthropic", connect("mcp-proxy.anthropic.com", 443), Ask, "claude:other-host", true},
		{"claude.com sub", connect("x.claude.com", 443), Ask, "claude:other-host", true},
		{"whole-host rule connect", connect("tools.example.com", 443), Free, "whole-host", false},
		{"method rule at connect asks", connect("api.github.com", 443), Ask, "default:unknown-host", true},
		{"expired rule", connect("old.example.com", 443), Ask, "default:unknown-host", true},
		{"trusted get", get("go.dev", "/doc"), Free, "trusted", false},
		{"unknown get", get("unknown.io", "/"), Ask, "default:unknown-host", true},
		{"rule free get", get("api.github.com", "/repos/o/r"), Free, "api-gh-read", false},
		{"deny rule wins by path", get("api.github.com", "/gists/1"), Deny, "block-gists", false},
		{"ask rule", post("api.github.com", "/repos/o/r/issues", "application/json", `{}`), Ask, "issues", true},
		{"auto rule", post("registry.npmjs.org", "/-/npm/v1/security/advisories/bulk", "application/json", `{}`), Ask, "npm-audit", false},
		{"auto rule other container", func() Request {
			r := post("registry.npmjs.org", "/-/npm/v1/security/advisories/bulk", "application/json", `{}`)
			r.Container = "lea-b"
			return r
		}(), Ask, "default:write", true},
		{"write to trusted asks", post("github.com", "/o/r/info", "application/json", `{}`), Ask, "default:write", true},
		{"messaging", post("hooks.slack.com", "/services/x", "application/json", `{}`), Ask, "default:messaging", true},
		{"publish", func() Request {
			r := post("registry.npmjs.org", "/pkg", "application/json", `{}`)
			r.Method = "PUT"
			return r
		}(), Ask, "default:publish", true},
		{"receive-pack", post("github.com", "/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", "0000"), Ask, "default:receive-pack", true},
		{"upload multipart", post("unknown.io", "/up", "multipart/form-data; boundary=x", "--x--"), Ask, "default:upload", true},
		{"websocket", func() Request { r := get("unknown.io", "/ws"); r.Header.Set("Upgrade", "websocket"); return r }(), Ask, "default:websocket", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := decideAll(p, c.r)
			if d.Verdict != c.verdict || d.Rule != c.rule || (d.Verdict == Ask && d.NeverAuto != c.neverAuto) {
				t.Fatalf("got %s rule=%s neverAuto=%v, want %s rule=%s neverAuto=%v (%+v)", d.Verdict, d.Rule, d.NeverAuto, c.verdict, c.rule, c.neverAuto, d)
			}
		})
	}
}

func TestConnectWarnsReadsAndWrites(t *testing.T) {
	d := decideAll(pol(t, ""), connect("unknown.io", 443))
	if len(d.Warnings) == 0 || !strings.Contains(d.Warnings[0], "reads AND writes") || !d.Red {
		t.Fatalf("connect ask must warn in red: %+v", d)
	}
}

func TestAutoRuleUploadNeverAuto(t *testing.T) {
	p := pol(t, "")
	r := post("registry.npmjs.org", "/-/npm/v1/security/advisories/bulk", "multipart/form-data; boundary=b", "--b--")
	if d := decideAll(p, r); d.Verdict != Ask || !d.NeverAuto {
		t.Fatalf("auto rule must not auto-approve an upload: %+v", d)
	}
	big := post("registry.npmjs.org", "/-/npm/v1/security/advisories/bulk", "application/json", strings.Repeat("a", 300<<10))
	if d := decideAll(p, big); d.Verdict != Ask || !d.NeverAuto {
		t.Fatalf("over max_body must ask a human: %+v", d)
	}
}

func TestBodyLimit(t *testing.T) {
	p := pol(t, "buffer_limit = \"1KiB\"\n")
	d := decideAll(p, post("unknown.io", "/x", "application/json", strings.Repeat("a", 2048)))
	if d.Verdict != Deny || d.Code != product.CodeBodyTooLarge {
		t.Fatalf("got %+v", d)
	}
}

func TestShadowMode(t *testing.T) {
	p := pol(t, "mode = \"shadow\"\n")
	d := decideAll(p, connect("unknown.io", 443))
	if d.Verdict != Free || d.Shadow != Ask {
		t.Fatalf("shadow: %+v", d)
	}
	d = decideAll(p, post("unknown.io", "/x?k=ghp_"+strings.Repeat("a", 36), "", ""))
	if d.Verdict != Deny || d.Code != product.CodeSecretEgress {
		t.Fatalf("secrets stay enforced in shadow: %+v", d)
	}
}

func TestShadowKeepsDenyListAndTrustedAnthropicDocs(t *testing.T) {
	if d := decideAll(pol(t, "mode = \"shadow\"\n"), connect("evil.example", 443)); d.Verdict != Deny {
		t.Fatalf("shadow lifted the deny list: %+v", d)
	}
	p := pol(t, "")
	p.Trusted = append(p.Trusted, "docs.anthropic.com")
	if d := decideAll(p, get("docs.anthropic.com", "/en/docs")); d.Verdict != Free {
		t.Fatalf("trusted Anthropic docs: %+v", d)
	}
	if d := decideAll(p, post("api.anthropic.com", "/v1/messages", "application/json", `{"mcp_servers":[{"url":"x"}]}`)); d.Verdict != Ask {
		t.Fatalf("Claude hosts keep their allowlist: %+v", d)
	}
	if _, err := policy.Parse([]byte("[profiles.default]\n[[profiles.default.internal_hosts]]\nhost = \"*.corp.example\"\nports = [443]\n"), "c", "default"); err == nil {
		t.Fatal("wildcard internal host accepted")
	}
}

func TestNoPolicy(t *testing.T) {
	if d := decideAll(nil, connect("api.anthropic.com", 443)); d.Verdict != Free {
		t.Fatalf("claude without policy: %+v", d)
	}
	if d := decideAll(nil, connect("go.dev", 443)); d.Verdict != Ask {
		t.Fatalf("no policy must ask: %+v", d)
	}
}

func TestSecrets(t *testing.T) {
	p := pol(t, "")
	tok := "ghp_" + strings.Repeat("A1b2", 9)
	r := get("unknown.io", "/")
	r.Header.Set("Authorization", "token "+tok)
	if d := decideAll(p, r); d.Verdict != Deny || d.Code != product.CodeSecretEgress {
		t.Fatalf("token to another host: %+v", d)
	}
	r = get("api.github.com", "/user")
	r.Header.Set("Authorization", "token "+tok)
	if d := decideAll(p, r); d.Verdict != Free {
		t.Fatalf("token to its host: %+v", d)
	}
	b := post("pastebin.example", "/", "text/plain", "key: sk-ant-api03-"+strings.Repeat("x", 30))
	if d := decideAll(p, b); d.Code != product.CodeSecretEgress {
		t.Fatalf("key in body: %+v", d)
	}
}

func TestHeuristics(t *testing.T) {
	blob := "q=aZ3kP9xQ2mW7vB4nL8cR1tY6uI0oE5sD&r=Zq8wX2nM5bV7cK1jH4gF6dS9aP3oI0uY"
	enforce := pol(t, "heuristics = \"enforce\"\n")
	r := get("go.dev", "/search")
	r.RawQuery = blob
	d := decideAll(enforce, r)
	if d.Verdict != Ask || !d.Red || !d.NeverAuto || d.Score < ScoreThreshold {
		t.Fatalf("enforce: %+v", d)
	}
	shadow := pol(t, "")
	d = decideAll(shadow, r)
	if d.Verdict != Free || d.Score < ScoreThreshold {
		t.Fatalf("shadow heuristics: %+v", d)
	}
	// Presigned URLs and digests are exempt.
	r2 := get("go.dev", "/x")
	r2.RawQuery = "X-Amz-Signature=" + strings.Repeat("ab12cd34", 8) + "&digest=sha256:" + strings.Repeat("a", 64)
	if s, why := Score(r2); s >= ScoreThreshold {
		t.Fatalf("exempt params scored %d: %v", s, why)
	}
	r3 := get(strings.Repeat("x", 45)+".evil.example", "/")
	if s, _ := Score(r3); s < 2 {
		t.Fatalf("long label not scored")
	}
	r4 := get("go.dev", "/x")
	r4.RawQuery = "to=jane.doe%40example.com"
	if s, _ := Score(r4); s < 2 {
		t.Fatalf("email in URL not scored")
	}
}

type fakeCreds map[string][]string

func (f fakeCreds) Known(container, via, sum string) (bool, bool) {
	key := container
	if via == "keyproxy" {
		key = "keyproxy"
	}
	for _, s := range f[key] {
		if s == sum {
			return true, true
		}
	}
	return true, false
}

func TestClaudeAPI(t *testing.T) {
	p := pol(t, "")
	ev := func(r Request, c Credentials) Decision {
		if d, stop := Floor(p, r); stop {
			return d
		}
		return Evaluate(p, r, now, c)
	}
	msg := func(body string) Request { return post("api.anthropic.com", "/v1/messages", "application/json", body) }
	cases := []struct {
		name    string
		r       Request
		verdict Verdict
	}{
		{"plain messages", msg(`{"model":"m","messages":[]}`), Free},
		{"client tools", msg(`{"tools":[{"name":"Bash","input_schema":{}},{"type":"bash_20250124","name":"bash"}]}`), Free},
		{"web_search", msg(`{"tools":[{"type":"web_search_20250305","name":"web_search"}]}`), Free},
		{"web_fetch", msg(`{"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}`), Ask},
		{"code_execution", msg(`{"tools":[{"type":"code_execution_20250825","name":"x"}]}`), Ask},
		{"mcp_servers", msg(`{"mcp_servers":[{"type":"url","url":"https://mcp.evil/sse","name":"x"}]}`), Ask},
		{"empty mcp_servers", msg(`{"mcp_servers":[]}`), Free},
		{"not json", msg(`nope`), Ask},
		{"count tokens", post("api.anthropic.com", "/v1/messages/count_tokens", "application/json", `{}`), Free},
		{"files", post("api.anthropic.com", "/v1/files", "multipart/form-data; boundary=b", "--b--"), Ask},
		{"other path", post("api.anthropic.com", "/v1/batches", "application/json", `{}`), Ask},
		{"oauth", post("console.anthropic.com", "/v1/oauth/token", "application/json", `{}`), Free},
		{"read", get("api.anthropic.com", "/api/oauth/profile"), Free},
		{"other host", get("artifacts.claude.ai", "/"), Ask},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := ev(c.r, NoCredentials{})
			if d.Verdict != c.verdict {
				t.Fatalf("got %+v", d)
			}
			if d.Verdict == Ask && !d.NeverAuto {
				t.Fatalf("Claude ASK must be NeverAuto: %+v", d)
			}
		})
	}
	good, bad := "sk-ant-oat01-good", "sk-ant-oat01-other"
	creds := fakeCreds{"lea-a": {sha(good)}, "keyproxy": {sha(bad)}}
	r := msg(`{}`)
	r.Header.Set("Authorization", "Bearer "+good)
	if d := ev(r, creds); d.Verdict != Free {
		t.Fatalf("own credential: %+v", d)
	}
	r.Header.Set("Authorization", "Bearer "+bad)
	if d := ev(r, creds); d.Verdict != Deny || d.Code != product.CodeSecretEgress {
		t.Fatalf("third-party key: %+v", d)
	}
	r.Via = "keyproxy"
	if d := ev(r, creds); d.Verdict != Free {
		t.Fatalf("keyproxy key: %+v", d)
	}
}

func TestClaudeAmbiguity(t *testing.T) {
	p := pol(t, "")
	for name, body := range map[string]string{
		"case variant":   `{"MCP_Servers":[{"url":"https://x"}]}`,
		"duplicate key":  `{"tools":[],"tools":[{"type":"web_fetch_20250910"}]}`,
		"tool type case": `{"tools":[{"Type":"web_fetch_20250910"}]}`,
		"trailing":       `{} {"mcp_servers":[{}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			d := decideAll(p, post("api.anthropic.com", "/v1/messages", "application/json", body))
			if d.Verdict != Ask {
				t.Fatalf("ambiguous body passed: %+v", d)
			}
		})
	}
	r := post("api.anthropic.com", "/v1/messages", "application/json", `{}`)
	r.Header.Add("Authorization", "Bearer a")
	r.Header.Add("Authorization", "Bearer b")
	if d, _ := claudeCredential(r, fakeCreds{"lea-a": {sha("a")}}); d.Verdict != Deny {
		t.Fatalf("two Authorization headers: %+v", d)
	}
}
