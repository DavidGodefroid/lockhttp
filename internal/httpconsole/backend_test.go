package httpconsole

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

// The console serves the policy only: the gate asks lockhub about held
// requests, so no method lets a caller ask the console's human.
func TestServesPolicyOnly(t *testing.T) {
	b, _ := setup(t)
	ms := b.Methods()
	if len(ms) != 1 || ms[wire.MethodPolicy] == nil {
		t.Fatalf("methods: %v", ms)
	}
	if ms["http.approve"] != nil {
		t.Fatal("the console still serves http.approve")
	}
}
