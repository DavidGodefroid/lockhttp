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
	"strings"
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
	if err := check(&p); err != nil {
		return console.ErrResp(req.ID, ipc.CodeInvalidParams, err.Error())
	}
	pol, _ := approvedPolicy(env)
	neverAuto := p.NeverAuto || !b.autoAllowed(pol, p)
	b.approvals.Add(1)
	a := env.Approve(ctx, req.ID, console.Screen{
		Header:    header(p),
		Requester: requester(p),
		Body:      body(p),
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

// check bounds what the gate sends.
func check(p *wire.ApproveParams) error {
	if p.Host == "" || p.Method == "" {
		return fmt.Errorf("host and method are required")
	}
	for _, s := range []*string{&p.RequestID, &p.Container, &p.Project, &p.Via, &p.Agent, &p.Attribution, &p.Role,
		&p.Parent, &p.TaskID, &p.Branch, &p.SessionID, &p.Phase, &p.TLS, &p.Method, &p.Host, &p.Path,
		&p.QueryHash, &p.BodyFP, &p.ContentType, &p.Rule, &p.Class, &p.ReplayOf} {
		if len(*s) > wire.MaxText {
			*s = (*s)[:wire.MaxText] + "…"
		}
	}
	if len(p.Preview) > wire.MaxPreview {
		p.Preview = p.Preview[:wire.MaxPreview] + "…"
	}
	if len(p.Warnings) > wire.MaxWarnings {
		p.Warnings = p.Warnings[:wire.MaxWarnings]
	}
	if len(p.Refs) > wire.MaxRefs {
		p.Refs = p.Refs[:wire.MaxRefs]
	}
	return nil
}

func header(p wire.ApproveParams) string {
	target := p.Host
	if p.Port != 0 && p.Port != 443 && p.Port != 80 {
		target = fmt.Sprintf("%s:%d", p.Host, p.Port)
	}
	if p.Phase == "connect" {
		return "OPEN " + target + " · " + p.Container
	}
	return p.Method + " " + target + " · " + p.Container
}

func requester(p wire.ApproveParams) string {
	s := "container " + p.Container
	if p.Project != "" {
		s += " (project " + p.Project + ")"
	}
	if p.Agent != "" {
		s += " · agent " + p.Agent + " (declared, " + p.Attribution + ")"
	}
	if p.Via != "" && p.Via != "direct" {
		s += " · via " + p.Via
	}
	return s
}

func body(p wire.ApproveParams) []string {
	var out []string
	if p.Phase == "connect" {
		out = append(out, fmt.Sprintf("CONNECT %s:%d", p.Host, p.Port))
		if p.Grant > 0 {
			out = append(out, fmt.Sprintf("y opens %s:%d for %s for %s: reads AND writes, content invisible", p.Host, p.Port, p.Container, time.Duration(p.Grant)*time.Second))
		}
	} else {
		line := p.Method + " " + p.TLS + "://" + p.Host + p.Path
		if p.QueryLen > 0 {
			line += fmt.Sprintf("?…(%d bytes)", p.QueryLen)
		}
		out = append(out, line)
		if p.ReqBytes > 0 || p.ContentType != "" {
			out = append(out, fmt.Sprintf("body %d bytes %s %s", p.ReqBytes, p.ContentType, short(p.BodyFP)))
		}
		if len(p.ReqHeaders) > 0 {
			out = append(out, "headers: "+strings.Join(p.ReqHeaders, " "))
		}
	}
	if p.TaskID != "" || p.Branch != "" || p.Role != "" {
		out = append(out, strings.TrimSpace(fmt.Sprintf("task %s · role %s · parent %s · branch %s", p.TaskID, p.Role, p.Parent, p.Branch)))
	}
	if p.Rule != "" {
		out = append(out, "decided by: "+p.Rule)
	}
	for _, r := range p.Refs {
		out = append(out, "push "+r)
	}
	if p.Preview != "" {
		out = append(out, "", "preview (masked):")
		for _, l := range strings.Split(p.Preview, "\n") {
			out = append(out, "  "+l)
		}
	}
	if p.Pending > 1 {
		out = append(out, "", fmt.Sprintf("%d distinct requests pending under %s %s%s: y approves this one only", p.Pending, p.Method, p.Host, p.Path))
	}
	if p.ReplayOf != "" {
		out = append(out, "replay of "+p.ReplayOf+" with another body: not covered by its approval")
	}
	if p.ClientGone {
		out = append(out, "", "client gone: y lets the same request through once in the next 10 minutes")
	}
	out = append(out, "request "+p.RequestID)
	return out
}

func short(fp string) string {
	if len(fp) > 19 {
		return fp[:19] + "…"
	}
	return fp
}
