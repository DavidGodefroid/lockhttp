// Package httpconsole is lockhttp's console backend for lockkit: the
// method the gate calls (policy.get) and the policy read from the console
// account's config file. lockkit's console holds the terminal, the policy
// review and the audit log. The gate asks lockhub, never the console,
// about held requests: the console serves no approvals.
package httpconsole

import (
	"context"
	"fmt"
	"os"
	"regexp"

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
}

// Backend implements console.Backend.
type Backend struct {
	o Options
}

// New returns the backend of o.Profile.
func New(o Options) *Backend {
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
	return map[string]console.Handler{wire.MethodPolicy: b.policy}
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
func (b *Backend) Status(console.Session) any { return map[string]any{} }

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
