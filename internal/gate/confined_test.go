package gate

import (
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
)

// A sender the gate cannot tell runs confined (no sources.json) is refused
// with E_UNCONFINED, on a plain request and on a CONNECT, unless the
// policy sets unconfined = true on a non-production profile outside a
// managed require_confined_agent (lockkit#133).
func TestUnconfinedSourceRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*policy.Policy)
		why  string
	}{
		{"default", func(p *policy.Policy) { p.Unconfined = false }, "unconfined = true"},
		{"production", func(p *policy.Policy) { p.Unconfined, p.Production = true, true }, "never allowed on a production profile"},
		{"managed", func(p *policy.Policy) { p.Unconfined, p.RequireConfined = true, true }, "managed configuration requires a confined agent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := policy.Parse([]byte(testPolicy), "c", "default")
			if err != nil {
				t.Fatal(err)
			}
			c.edit(&p)
			e := newEnv(t, testPolicy, false, func(cfg *Config) { cfg.Console = &fakeConsole{pol: &p} })
			resp, err := e.client("dev-5", false).Get("http://trusted.test/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_UNCONFINED" ||
				!strings.Contains(string(body), ReasonNoSources) || !strings.Contains(string(body), c.why) {
				t.Fatalf("plain request: %s %v\n%s", resp.Status, resp.Header, body)
			}
			if resp, err := e.client("dev-5", false).Get("https://trusted.test/"); err == nil {
				resp.Body.Close()
				t.Fatalf("CONNECT of an unconfined sender served: %s", resp.Status)
			}
			a := e.auditText()
			for _, want := range []string{`"decision":"refused-unconfined"`, `"code":"E_UNCONFINED"`, `"unconfined":true`,
				`"unconfined_reasons":["` + ReasonNoSources + `"]`, `"method":"CONNECT"`} {
				if !strings.Contains(a, want) {
					t.Fatalf("audit lacks %s:\n%s", want, a)
				}
			}
		})
	}
}

// With unconfined = true the sender is served, and every record says it
// is unconfined.
func TestUnconfinedSourceServedAudited(t *testing.T) {
	e := newEnv(t, testPolicy, false, nil)
	resp, err := e.client("dev-5", false).Get("http://trusted.test:8080/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-LockHTTP-Code") == "E_UNCONFINED" {
		t.Fatalf("unconfined = true refused: %v", resp.Header)
	}
	if a := e.auditText(); !strings.Contains(a, `"unconfined":true`) || !strings.Contains(a, `"unconfined_reasons":["`+ReasonNoSources+`"]`) {
		t.Fatalf("audit does not mark the unconfined sender:\n%s", a)
	}
}

// A source named by lea's sources.json is one of its containers: confined.
func TestLeaSourceConfined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"networks":[{"local_ip":"10.89.3.2","container":"lea-a"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := NewSources(path).Resolve(netip.MustParseAddr("10.89.3.2"), "", "", "")
	if err != nil || len(src.Unconfined) != 0 {
		t.Fatalf("lea source: %+v %v", src, err)
	}
	if src, _ := NewSources("").Resolve(netip.MustParseAddr("127.0.0.1"), "", "", ""); strings.Join(src.Unconfined, ",") != ReasonNoSources {
		t.Fatalf("source without sources.json: %+v", src)
	}
}
