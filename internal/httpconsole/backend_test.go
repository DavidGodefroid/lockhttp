package httpconsole

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

type fakeEnv struct {
	pol     console.Policy
	screens []console.Screen
	answer  bool
	records []audit.Record
}

func (f *fakeEnv) Approve(ctx context.Context, id int64, s console.Screen) console.Approval {
	f.screens = append(f.screens, s)
	if s.Record != nil {
		f.records = append(f.records, s.Record(audit.Base{Event: "approved"}))
	}
	if !s.NeverAuto {
		return console.Approval{Approved: true, Auto: true}
	}
	if f.answer {
		return console.Approval{Approved: true}
	}
	return console.Approval{Refusal: console.ErrResp(id, ipc.CodeDenied, "denied by the human: no")}
}
func (f *fakeEnv) Auto() bool                                       { return true }
func (f *fakeEnv) ShowResults() bool                                { return false }
func (f *fakeEnv) UnmaskAllowed() bool                              { return false }
func (f *fakeEnv) Session(context.Context) (console.Session, error) { return session{}, nil }
func (f *fakeEnv) Lost()                                            {}
func (f *fakeEnv) Policy() console.Policy                           { return f.pol }
func (f *fakeEnv) Audit(audit.Record)                               {}
func (f *fakeEnv) AuditBase(context.Context, audit.Base)            {}
func (f *fakeEnv) Println(string)                                   {}
func (f *fakeEnv) Safe(s string) string                             { return s }
func (f *fakeEnv) Sanitizer() *sanitize.Sanitizer                   { return Sanitizer() }
func (f *fakeEnv) Level(context.Context, time.Time)                 {}
func (f *fakeEnv) End(string)                                       {}

const conf = `
[profiles.default]
[[profiles.default.rules]]
id = "audit"
container = "lea-a"
host = "registry.npmjs.org"
methods = ["POST"]
path = "/-/npm/v1/security/advisories/bulk"
verdict = "auto"

[[profiles.default.rules]]
id = "issues"
host = "api.github.com"
methods = ["POST"]
verdict = "ask"
`

func setup(t *testing.T) (*Backend, *fakeEnv) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Options{Profile: "default", Config: path})
	cp, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return b, &fakeEnv{pol: cp}
}

func call(t *testing.T, b *Backend, env *fakeEnv, method string, params any) ipc.Response {
	t.Helper()
	raw, _ := json.Marshal(params)
	return b.Methods()[method](context.Background(), ipc.Request{JSONRPC: "2.0", ID: 7, Method: method, Params: raw}, env)
}

func autoParams() wire.ApproveParams {
	return wire.ApproveParams{RequestID: "h-1", Source: wire.Source{Container: "lea-a", Agent: "dev-5", Attribution: "proxy-auth"},
		Target: wire.Target{Phase: "http", TLS: "mitm", Method: "POST", Host: "registry.npmjs.org", Port: 443, Path: "/-/npm/v1/security/advisories/bulk"},
		Rule:   "audit", RuleAuto: true, NeverAuto: false}
}

func TestAutoOnlyForApprovedAutoRule(t *testing.T) {
	b, env := setup(t)
	if r := call(t, b, env, wire.MethodApprove, autoParams()); r.Error != nil || env.screens[0].NeverAuto {
		t.Fatalf("matching auto rule should allow auto: %+v %+v", r.Error, env.screens)
	}
	cases := map[string]func(*wire.ApproveParams){
		"other container": func(p *wire.ApproveParams) { p.Container = "lea-b" },
		"other path":      func(p *wire.ApproveParams) { p.Path = "/pkg" },
		"other method":    func(p *wire.ApproveParams) { p.Method = "PUT" },
		"ask rule":        func(p *wire.ApproveParams) { p.Rule = "issues"; p.Host = "api.github.com"; p.Path = "/x" },
		"unknown rule":    func(p *wire.ApproveParams) { p.Rule = "nope" },
		"no claim":        func(p *wire.ApproveParams) { p.RuleAuto = false },
		"red":             func(p *wire.ApproveParams) { p.Red = true },
		"connect":         func(p *wire.ApproveParams) { p.Phase = "connect" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			p := autoParams()
			edit(&p)
			env.screens = nil
			r := call(t, b, env, wire.MethodApprove, p)
			if !env.screens[0].NeverAuto || r.Error == nil {
				t.Fatalf("auto allowed for a forged claim: %+v", env.screens[0])
			}
		})
	}
}

func TestApproveScreenAndRecord(t *testing.T) {
	b, env := setup(t)
	env.answer = true
	p := autoParams()
	p.RuleAuto, p.NeverAuto, p.ClientGone, p.Pending = false, true, true, 3
	p.Preview = strings.Repeat("x", 5000)
	r := call(t, b, env, wire.MethodApprove, p)
	var res wire.ApproveResult
	if r.Error != nil || json.Unmarshal(r.Result, &res) != nil || !res.Approved || res.Auto {
		t.Fatalf("approve: %+v %s", r.Error, r.Result)
	}
	text := strings.Join(env.screens[0].Body, "\n")
	for _, want := range []string{"client gone", "3 distinct requests", "preview (masked)", "request h-1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("screen lacks %q:\n%s", want, text)
		}
	}
	if len(text) > 3000 {
		t.Fatal("preview not capped")
	}
	rec, ok := env.records[0].(wire.Record)
	if !ok || rec.RequestID != "h-1" || rec.Container != "lea-a" || rec.Host != "registry.npmjs.org" || rec.Event != "approved" {
		t.Fatalf("record: %+v", env.records[0])
	}
	if !strings.Contains(env.screens[0].Requester, "declared") {
		t.Fatalf("agent must be shown as declared: %q", env.screens[0].Requester)
	}
}

func TestDenied(t *testing.T) {
	b, env := setup(t)
	p := autoParams()
	p.NeverAuto = true
	r := call(t, b, env, wire.MethodApprove, p)
	if r.Error == nil || r.Error.Code != ipc.CodeDenied {
		t.Fatalf("deny: %+v", r)
	}
}

func TestPolicyGet(t *testing.T) {
	b, env := setup(t)
	r := call(t, b, env, wire.MethodPolicy, nil)
	var res wire.PolicyResult
	if r.Error != nil || json.Unmarshal(r.Result, &res) != nil {
		t.Fatalf("policy.get: %+v", r)
	}
	if res.Fingerprint != env.pol.(policy.Policy).Fingerprint() || len(res.Policy.Rules) != 2 {
		t.Fatalf("policy: %+v", res)
	}
}

func TestInvalidParams(t *testing.T) {
	b, env := setup(t)
	r := call(t, b, env, wire.MethodApprove, wire.ApproveParams{})
	if r.Error == nil || r.Error.Code != ipc.CodeInvalidParams {
		t.Fatalf("empty params: %+v", r)
	}
}
