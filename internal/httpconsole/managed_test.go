//go:build lockfamily_managed_test

package httpconsole

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

const managedText = `version = 1
organisation = "Example Corp"

[lockhttp.bounds]
mode = "enforce"
heuristics = "enforce"
buffer_limit = "1MiB"
connect_grant = "5m"
idle_timeout = "1h"
max_session = "8h"
trusted = ["*.example.com"]
splice = []
redirect_cdn = []
internal_hosts = [{ host = "ci.internal", ports = [8080] }]
deny = ["paste.example.org"]

[[lockhttp.bounds.rules]]
id = "no-tools"
host = "tools.example.com"
verdict = "deny"

[lockhttp.profiles.corp]
mode = "enforce"
heuristics = "enforce"
buffer_limit = "1MiB"
connect_grant = "5m"
idle_timeout = "1h"
max_session = "8h"
deny = ["paste.example.org"]
`

// placeManaged makes managed.Load read text (test builds only).
func placeManaged(t *testing.T, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
}

func backendOn(t *testing.T, conf, profile string) *Backend {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(Options{Profile: profile, Config: path})
}

// lines checks p as the console does at start: one line per violation.
func lines(t *testing.T, b *Backend, p console.Policy) []string {
	t.Helper()
	m, err := managed.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return console.ManagedLines(console.CheckManaged(product.P, b, p, m))
}

func TestManagedBoundsOneViolationPerFamily(t *testing.T) {
	placeManaged(t, managedText)
	b := backendOn(t, `
[profiles.dev]
mode = "shadow"
heuristics = "shadow"
buffer_limit = "4MiB"
connect_grant = "10m"
trusted = ["api.example.com", "evil.example.org"]
splice = ["pinned.example.org"]
redirect_cdn = ["api.example.com>cdn.example.net"]
internal_hosts = [{ host = "ci.internal", ports = [8080, 9090] }]
`, "dev")
	p, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(lines(t, b, p), "\n")
	for _, want := range []string{
		"blocked by company policy: lockhttp.bounds.mode = enforce (profile dev: mode = shadow)",
		"blocked by company policy: lockhttp.bounds.heuristics = enforce (profile dev: heuristics = shadow)",
		"blocked by company policy: lockhttp.bounds.buffer_limit = 1MiB (profile dev: buffer_limit = 4MiB)",
		"blocked by company policy: lockhttp.bounds.connect_grant = 300s (profile dev: connect_grant = 600s)",
		"blocked by company policy: lockhttp.bounds.idle_timeout = 3600s (profile dev: idle_timeout = 86400s)",
		"blocked by company policy: lockhttp.bounds.trusted does not allow evil.example.org",
		"blocked by company policy: lockhttp.bounds.splice does not allow pinned.example.org",
		"blocked by company policy: lockhttp.bounds.redirect_cdn does not allow api.example.com>cdn.example.net",
		"blocked by company policy: lockhttp.bounds.internal_hosts does not allow ci.internal:9090 ask",
		"blocked by company policy: lockhttp.bounds.deny requires paste.example.org (profile dev: deny - paste.example.org)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "api.example.com (") || strings.Contains(got, "rules") {
		t.Errorf("a field within the bounds is cited:\n%s", got)
	}
}

func TestManagedBoundsWithinNoViolation(t *testing.T) {
	placeManaged(t, managedText)
	b := backendOn(t, `
[profiles.dev]
mode = "enforce"
heuristics = "enforce"
buffer_limit = "1MiB"
connect_grant = "1m"
idle_timeout = "1h"
max_session = "1h"
trusted = ["api.example.com"]
internal_hosts = [{ host = "ci.internal", ports = [8080] }]
deny = ["paste.example.org"]
`, "dev")
	p, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if got := lines(t, b, p); len(got) != 0 {
		t.Fatalf("violations: %v", got)
	}
	pol := p.(policy.Policy)
	if len(pol.ManagedRules) != 1 || pol.ManagedRules[0].ID != "no-tools" {
		t.Fatalf("LoadPolicy without the managed rules: %+v", pol.ManagedRules)
	}
	// The managed profile is served too, within its own bounds.
	b = backendOn(t, "[profiles.dev]\n", "corp")
	if p, err = b.LoadPolicy(); err != nil {
		t.Fatal(err)
	}
	if got := lines(t, b, p); len(got) != 0 {
		t.Fatalf("managed profile violations: %v", got)
	}
}

func TestManagedRuleRemovedIsViolation(t *testing.T) {
	placeManaged(t, managedText)
	b := backendOn(t, "[profiles.corp-dev]\ndeny = [\"paste.example.org\"]\n", "corp-dev")
	p, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	pol := p.(policy.Policy)
	pol.ManagedRules = nil
	got := strings.Join(lines(t, b, pol), "\n")
	if !strings.Contains(got, "lockhttp.bounds.rules requires deny * tools.example.com") {
		t.Fatalf("a policy without the managed rule: %s", got)
	}
}

func TestNoManagedFileNoBounds(t *testing.T) {
	managed.SetTestPath("")
	b := backendOn(t, "[profiles.dev]\nmode = \"shadow\"\n", "dev")
	p, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := console.CheckManaged(product.P, b, p, nil); err != nil {
		t.Fatal(err)
	}
}
