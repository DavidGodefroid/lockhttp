package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// unconfined = true is read into the profile and the console's Profile,
// changes the fingerprint (absent keeps it), and switching it on loosens.
func TestUnconfinedKey(t *testing.T) {
	base := mustParse(t, sample, "default")
	if base.Unconfined || base.Profile().Unconfined {
		t.Fatal("unconfined without the key")
	}
	if b, err := json.Marshal(base); err != nil || strings.Contains(string(b), "confined") {
		t.Fatal("a policy without unconfined carries the member: existing fingerprints would change")
	}
	on := mustParse(t, strings.Replace(sample, "[profiles.default]\n", "[profiles.default]\nunconfined = true\n", 1), "default")
	if !on.Unconfined || !on.Profile().Unconfined {
		t.Fatalf("unconfined = true not read: %+v", on.Profile())
	}
	if on.Fingerprint() == base.Fingerprint() {
		t.Fatal("unconfined does not change the fingerprint")
	}
	if got := loosened(on.Diff(base)); strings.Join(got, ",") != "unconfined" {
		t.Fatalf("switching unconfined on: loosened %v", got)
	}
	if got := loosened(base.Diff(on)); len(got) != 0 {
		t.Fatalf("switching unconfined off loosens %v", got)
	}
	if !strings.Contains(strings.Join(on.Describe(), "\n"), "unconfined = true") {
		t.Fatalf("Describe does not show unconfined: %q", on.Describe())
	}
}

func TestUnconfinedRefusal(t *testing.T) {
	var none *Policy
	cases := []struct {
		name string
		p    *Policy
		want string
	}{
		{"no policy", none, "no policy"},
		{"default", &Policy{}, "unconfined = true"},
		{"unconfined", &Policy{Unconfined: true}, ""},
		{"production", &Policy{Unconfined: true, Production: true}, "production"},
		{"managed", &Policy{Unconfined: true, RequireConfined: true}, "managed"},
	}
	for _, c := range cases {
		got := c.p.UnconfinedRefusal()
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The managed require_confined_agent is served in the policy, on a file
// profile and on a managed one.
func TestManagedRequireConfined(t *testing.T) {
	mg := mustManaged(t, "[family]\nrequire_confined_agent = true\n[lockhttp.profiles.corp]\nunconfined = true\n")
	for _, profile := range []string{"default", "corp"} {
		p, err := ParseManaged([]byte(sample), "config.toml", profile, mg)
		if err != nil {
			t.Fatal(err)
		}
		if !p.RequireConfined || !strings.Contains(p.UnconfinedRefusal(), "managed") {
			t.Fatalf("%s: require_confined_agent not served: %+v", profile, p)
		}
	}
	p, err := ParseManaged([]byte(sample), "config.toml", "default", mustManaged(t, ""))
	if err != nil || p.RequireConfined {
		t.Fatalf("without require_confined_agent: %v, %+v", err, p)
	}
}
