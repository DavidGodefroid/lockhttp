package decide

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// withManaged is the test policy with extra profile keys and managed
// rules, as LoadPolicy builds it from the company's managed file.
func withManaged(t *testing.T, extra string, rules ...policy.Rule) *policy.Policy {
	t.Helper()
	p := pol(t, extra)
	p.ManagedRules = rules
	q := policy.Canonical(*p)
	return &q
}

var (
	managedDenyTools = policy.Rule{ID: "no-tools", Host: "tools.example.com", Verdict: policy.VerdictDeny}
	managedAskNPM    = policy.Rule{ID: "ask-npm", Host: "registry.npmjs.org", Verdict: policy.VerdictAsk}
	managedDenyGists = policy.Rule{ID: "no-gists", Host: "api.github.com", Path: "/gists*", Verdict: policy.VerdictDeny}
)

func TestManagedDenyBeatsUserFree(t *testing.T) {
	p := withManaged(t, "", managedDenyTools)
	for _, r := range []Request{get("tools.example.com", "/x"), post("tools.example.com", "/x", "application/json", "{}"), connect("tools.example.com", 443)} {
		d := decideAll(p, r)
		if d.Verdict != Deny || d.Rule != "managed:no-tools" || d.Code != product.CodeRule {
			t.Fatalf("%s %s: managed deny lifted by the user's free rule: %+v", r.Phase, r.Method, d)
		}
	}
	// Hard: no grant lifts it either.
	if d, ok := Hard(p, get("tools.example.com", "/x"), now); !ok || d.Verdict != Deny {
		t.Fatalf("Hard: %+v %v", d, ok)
	}
	// Without the managed rule, the user's rule applies.
	if d := decideAll(pol(t, ""), get("tools.example.com", "/x")); d.Verdict != Free {
		t.Fatalf("user free rule: %+v", d)
	}
}

func TestManagedAskBeatsUserAuto(t *testing.T) {
	p := withManaged(t, "", managedAskNPM)
	r := post("registry.npmjs.org", "/-/npm/v1/security/advisories/bulk", "application/json", "{}")
	if d := decideAll(pol(t, ""), r); d.Verdict != Ask || d.NeverAuto {
		t.Fatalf("user auto rule: %+v", d)
	}
	d := decideAll(p, r)
	if d.Verdict != Ask || !d.NeverAuto || d.Rule != "managed:ask-npm" {
		t.Fatalf("managed ask lifted by the user's auto rule: %+v", d)
	}
	// A trusted read becomes a human's too.
	if d := decideAll(p, get("registry.npmjs.org", "/pkg")); d.Verdict != Ask || !d.NeverAuto {
		t.Fatalf("managed ask on a trusted read: %+v", d)
	}
}

func TestUserDenyStaysDeny(t *testing.T) {
	p := withManaged(t, "", managedAskNPM, policy.Rule{ID: "ask-gh", Host: "api.github.com", Verdict: policy.VerdictAsk})
	if d := decideAll(p, get("api.github.com", "/gists/1")); d.Verdict != Deny || d.Rule != "block-gists" {
		t.Fatalf("user deny under a managed ask: %+v", d)
	}
	if d := decideAll(p, connect("evil.example", 443)); d.Verdict != Deny || d.Rule != "deny-list" {
		t.Fatalf("deny list: %+v", d)
	}
}

func TestManagedDecisionNotRelaxedInShadow(t *testing.T) {
	for _, extra := range []string{"mode = \"shadow\"\n", "heuristics = \"shadow\"\n", "mode = \"shadow\"\nheuristics = \"shadow\"\n"} {
		p := withManaged(t, extra, managedDenyTools, managedAskNPM)
		if d := decideAll(p, get("tools.example.com", "/x")); d.Verdict != Deny {
			t.Errorf("%q: managed deny relaxed: %+v", extra, d)
		}
		if d := decideAll(p, get("registry.npmjs.org", "/pkg")); d.Verdict != Ask || d.Shadow != "" {
			t.Errorf("%q: managed ask relaxed: %+v", extra, d)
		}
		// What no managed rule decides is still relaxed in shadow mode.
		if strings.Contains(extra, "mode") {
			if d := decideAll(p, connect("unknown.io", 443)); d.Verdict != Free || d.Shadow != Ask {
				t.Errorf("%q: shadow mode lost: %+v", extra, d)
			}
		}
	}
}

func TestManagedRuleAtTheDomain(t *testing.T) {
	// A managed rule with a path cannot be told apart at the domain: the
	// CONNECT asks; the decrypted request is denied.
	p := withManaged(t, "", managedDenyGists)
	if _, ok := Hard(p, connect("api.github.com", 443), now); ok {
		t.Fatal("a path rule denies the whole host at the domain")
	}
	if d := decideAll(p, connect("api.github.com", 443)); d.Verdict != Ask || !d.NeverAuto {
		t.Fatalf("CONNECT under a managed path rule: %+v", d)
	}
	if d := decideAll(p, get("api.github.com", "/gists/2")); d.Verdict != Deny || d.Rule != "managed:no-gists" {
		t.Fatalf("decrypted request: %+v", d)
	}
	if d := decideAll(p, get("api.github.com", "/repos/o/r")); d.Verdict != Free {
		t.Fatalf("outside the managed rule: %+v", d)
	}
}

func TestManagedRuleExpiresAndContainer(t *testing.T) {
	p := withManaged(t, "",
		policy.Rule{ID: "old", Host: "tools.example.com", Verdict: policy.VerdictDeny, Expires: "2026-01-01"},
		policy.Rule{ID: "other", Container: "lea-b", Host: "tools.example.com", Verdict: policy.VerdictDeny})
	if d := decideAll(p, get("tools.example.com", "/x")); d.Verdict != Free {
		t.Fatalf("expired or other container's managed rule applied: %+v", d)
	}
}

func TestFloorBeatsManagedRules(t *testing.T) {
	p := withManaged(t, "", policy.Rule{ID: "ask-all", Host: "*", Verdict: policy.VerdictAsk})
	if d := decideAll(p, connect("metadata.google.internal", 443)); d.Verdict != Deny || !strings.HasPrefix(d.Rule, "floor:") {
		t.Fatalf("floor: %+v", d)
	}
	if d := decideAll(p, connect("1.2.3.4", 443)); d.Verdict != Deny || !strings.HasPrefix(d.Rule, "floor:") {
		t.Fatalf("floor: %+v", d)
	}
	// Internal hosts and Claude are under the managed rules too.
	if d := decideAll(p, get("ci", "/")); d.Verdict != Ask {
		t.Fatalf("internal read under a managed ask: %+v", d)
	}
}

func TestManagedDenyStrictestWins(t *testing.T) {
	p := withManaged(t, "",
		policy.Rule{ID: "ask-gh", Host: "api.github.com", Path: "/repos*", Verdict: policy.VerdictAsk},
		policy.Rule{ID: "deny-gh", Host: "*.github.com", Verdict: policy.VerdictDeny})
	if d := decideAll(p, get("api.github.com", "/repos/o/r")); d.Verdict != Deny || d.Rule != "managed:deny-gh" {
		t.Fatalf("a more specific managed ask lifted a managed deny: %+v", d)
	}
}
