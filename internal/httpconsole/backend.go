// Package httpconsole is lockhttp's console backend for lockkit: the
// methods the gate calls (http.approve, policy.get) and the policy read
// from the console account's config file. lockkit's console holds the
// terminal, the approval screens, the modes, the policy review and the
// audit log.
package httpconsole

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// Options locate the profile a console serves.
type Options struct {
	Profile string
	// Config is the config file (the console account's
	// ~/.config/lockhttp/config.toml).
	Config string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Backend implements console.Backend.
type Backend struct {
	o Options

	approvals, approved atomic.Int64
}

// New returns the backend of o.Profile.
func New(o Options) *Backend {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Backend{o: o}
}

var _ console.Backend = (*Backend)(nil)

// Sanitizer scrubs lockhttp's error text: URL userinfo and Authorization
// or Proxy-Authorization headers.
func Sanitizer() *sanitize.Sanitizer {
	return sanitize.New(sanitize.URLUserinfo, regexp.MustCompile(`(?i)(proxy-)?authorization:\s*[^\r\n]*`))
}

// Methods implements console.Backend.
func (b *Backend) Methods() map[string]console.Handler {
	return map[string]console.Handler{wire.MethodApprove: b.approve, wire.MethodPolicy: b.policy}
}

type session struct{}

func (session) Close() error { return nil }

// Connect implements console.Backend: the console guards no backend
// connection of its own (the gate sends the requests), so there is
// nothing to log in to.
func (b *Backend) Connect(context.Context, console.Credentials) (console.Session, error) {
	return session{}, nil
}

// Checks implements console.Backend.
func (b *Backend) Checks(context.Context, console.Session) []console.Finding { return nil }

// LoadPolicy implements console.Backend: the profile from the config file.
func (b *Backend) LoadPolicy() (console.Policy, error) {
	data, err := os.ReadFile(b.o.Config)
	if err != nil {
		return nil, fmt.Errorf("reading the policy: %w (create it with: lockhttp init)", err)
	}
	p, err := policy.Parse(data, b.o.Config, b.o.Profile)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Status implements console.Backend.
func (b *Backend) Status(console.Session) any {
	return map[string]any{"approvals": b.approvals.Load(), "approved": b.approved.Load()}
}

func (b *Backend) policy(_ context.Context, req ipc.Request, env console.Env) ipc.Response {
	p, ok := approvedPolicy(env)
	if !ok {
		return console.ErrResp(req.ID, ipc.CodeInternal, "the console holds no lockhttp policy")
	}
	return console.OKResp(req.ID, wire.PolicyResult{Policy: p, Fingerprint: p.Fingerprint()})
}

func approvedPolicy(env console.Env) (policy.Policy, bool) {
	switch p := env.Policy().(type) {
	case policy.Policy:
		return p, true
	case *policy.Policy:
		if p != nil {
			return *p, true
		}
	}
	return policy.Policy{}, false
}

func (b *Backend) approve(ctx context.Context, req ipc.Request, env console.Env) ipc.Response {
	var p wire.ApproveParams
	if r := console.Decode(req, &p); r != nil {
		return *r
	}
	if err := wire.Bound(&p); err != nil {
		return console.ErrResp(req.ID, ipc.CodeInvalidParams, err.Error())
	}
	pol, _ := approvedPolicy(env)
	neverAuto := p.NeverAuto || !b.autoAllowed(pol, p)
	b.approvals.Add(1)
	a := env.Approve(ctx, req.ID, console.Screen{
		Header:    wire.ScreenHeader(p),
		Requester: wire.ScreenRequester(p),
		Body:      wire.ScreenBody(p),
		Warnings:  p.Warnings,
		NeverAuto: neverAuto,
		Red:       p.Red,
		Record: func(base audit.Base) audit.Record {
			return wire.Record{Base: base, RequestID: p.RequestID, Source: p.Source, Target: p.Target,
				Rule: p.Rule, Class: p.Class, Score: p.Score, PolicyFP: pol.Fingerprint()}
		},
	})
	if !a.Approved {
		return a.Refusal
	}
	b.approved.Add(1)
	return console.OKResp(req.ID, wire.ApproveResult{Approved: true, Auto: a.Auto})
}

// autoAllowed re-checks, against the console's own approved policy, the
// gate's claim that a verdict="auto" rule matched: the rule exists, is
// active, says auto, may be auto, and matches the request. Anything else
// keeps the screen NeverAuto, whatever the gate says.
func (b *Backend) autoAllowed(pol policy.Policy, p wire.ApproveParams) bool {
	if !p.RuleAuto || p.Red || p.Phase != "http" || pol.Production {
		return false
	}
	for _, r := range pol.Rules {
		if r.ID != p.Rule {
			continue
		}
		return r.Verdict == policy.VerdictAuto && r.Active(b.o.Now()) && pol.AutoForbidden(r) == "" &&
			policy.HostMatch(r.Host, p.Host) && r.MatchesMethod(p.Method) && r.MatchesPath(p.Path) &&
			(r.Container == "" || r.Container == p.Container) && !pol.Spliced(p.Host) &&
			(r.MaxBody == 0 || p.ReqBytes <= r.MaxBody)
	}
	return false
}
