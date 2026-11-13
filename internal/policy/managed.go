package policy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// ManagedRulePrefix starts the Rule of a decision made by a managed rule
// ("managed:<id>"): shadow mode never relaxes it.
const ManagedRulePrefix = "managed:"

// managedRuleField is the Diff field of a managed rule.
const managedRuleField = "managed rule "

// Managed is lockhttp's section of the company's managed file, checked:
// its profiles, defaults, bounds and rules. A user may tighten what it
// allows, never loosen it.
type Managed struct {
	// File is the managed file it was read from.
	File *managed.File
	// Rules are [[lockhttp.bounds.rules]]: deny or ask rules no user rule
	// lifts, canonical (sorted by id).
	Rules    []Rule
	Bounds   Bounds
	defaults rawDefaults
	profiles map[string]Policy
}

// Bounds are [lockhttp.bounds] without its rules. A zero field bounds
// nothing; a nil list bounds nothing, an empty one allows no entry.
type Bounds struct {
	Production  bool
	Mode        string
	Heuristics  string
	BufferLimit int64
	// Durations, in seconds.
	ConnectGrant, IdleTimeout, MaxSession int64
	// Allowed lists: a profile entry must be within one of them.
	Trusted, Splice, RedirectCDN []string
	Internal                     []InternalHost
	// Deny is required: every entry must be on the profile's deny list.
	Deny []string
}

// rawDefaults is [lockhttp.defaults]: the scalar keys of a profile. A key
// set fills a profile that leaves it unset.
type rawDefaults struct {
	Production   *bool   `toml:"production"`
	Mode         *string `toml:"mode"`
	Heuristics   *string `toml:"heuristics"`
	BufferLimit  *string `toml:"buffer_limit"`
	Hold         *string `toml:"hold"`
	ConnectGrant *string `toml:"connect_grant"`
	IdleTimeout  *string `toml:"idle_timeout"`
	MaxSession   *string `toml:"max_session"`
}

// rawBounds is the TOML shape of [lockhttp.bounds]. hold and inject are
// not keys: hold never loosens, and injections are out of its reach.
type rawBounds struct {
	Production   *bool     `toml:"production"`
	Mode         string    `toml:"mode"`
	Heuristics   string    `toml:"heuristics"`
	BufferLimit  string    `toml:"buffer_limit"`
	ConnectGrant string    `toml:"connect_grant"`
	IdleTimeout  string    `toml:"idle_timeout"`
	MaxSession   string    `toml:"max_session"`
	Trusted      *[]string `toml:"trusted"`
	Splice       *[]string `toml:"splice"`
	RedirectCDN  *[]string `toml:"redirect_cdn"`
	Internal     *[]rawIH  `toml:"internal_hosts"`
	Deny         []string  `toml:"deny"`
	Rules        []rawRule `toml:"rules"`
}

// LoadManaged reads lockhttp's section of m: nil and no error when m is
// nil. An invalid key, a bound or rule that does not check, a default
// beyond the bounds or a managed profile beyond them is an error.
func LoadManaged(m *managed.File) (*Managed, error) {
	if m == nil {
		return nil, nil
	}
	tool := product.P.Name
	mg := &Managed{File: m, profiles: map[string]Policy{}}
	var rb rawBounds
	if _, err := m.Decode(&rb, tool, managed.KindBounds); err != nil {
		return nil, err
	}
	var err error
	if mg.Bounds, mg.Rules, err = boundsFromRaw(rb); err != nil {
		return nil, fmt.Errorf("managed: [%s.%s]: %w", tool, managed.KindBounds, err)
	}
	if _, err := m.Decode(&mg.defaults, tool, managed.KindDefaults); err != nil {
		return nil, err
	}
	if err := mg.checkDefaults(); err != nil {
		return nil, fmt.Errorf("managed: [%s.%s]: %w", tool, managed.KindDefaults, err)
	}
	for _, name := range m.Profiles(tool) {
		var r raw
		if _, err := m.Decode(&r, tool, managed.KindProfiles, name); err != nil {
			return nil, err
		}
		var keys map[string]any
		if _, err := m.Decode(&keys, tool, managed.KindProfiles, name); err != nil {
			return nil, err
		}
		mg.defaults.apply(&r, func(k string) bool { _, ok := keys[k]; return ok })
		p, err := fromRaw(name, r)
		if err != nil {
			return nil, fmt.Errorf("managed: [%s.%s.%s]: %w", tool, managed.KindProfiles, name, err)
		}
		p.ManagedRules = slices.Clone(mg.Rules)
		p = Canonical(p)
		if vs := mg.Check(p); len(vs) > 0 {
			return nil, fmt.Errorf("managed: [%s.%s.%s] is beyond the bounds: %s", tool, managed.KindProfiles, name, beyond(vs[0]))
		}
		mg.profiles[name] = p
	}
	return mg, nil
}

// ProfileNames lists the managed profiles, sorted (nil Managed: none).
func (mg *Managed) ProfileNames() []string {
	if mg == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(mg.profiles))
}

// Bounded reports whether mg bounds anything of a policy: a bound or a
// managed rule.
func (mg *Managed) Bounded() bool {
	if mg == nil {
		return false
	}
	b := mg.Bounds
	return b.Production || b.Mode != "" || b.Heuristics != "" || b.BufferLimit > 0 || b.ConnectGrant > 0 ||
		b.IdleTimeout > 0 || b.MaxSession > 0 || b.Trusted != nil || b.Splice != nil || b.RedirectCDN != nil ||
		b.Internal != nil || len(b.Deny) > 0 || len(mg.Rules) > 0
}

// Ceiling is p with every bounded field set to its bound: the loosest
// policy mg allows for p. p's own Diff against it tells what goes beyond.
func (mg *Managed) Ceiling(p Policy) Policy {
	c := p.Clone()
	b := mg.Bounds
	if b.Production {
		c.Production = true
	}
	if b.Mode != "" {
		c.Mode = b.Mode
	}
	if b.Heuristics != "" {
		c.Heuristics = b.Heuristics
	}
	for _, f := range []struct {
		bound int64
		to    *int64
	}{{b.BufferLimit, &c.BufferLimit}, {b.ConnectGrant, &c.ConnectGrant}, {b.IdleTimeout, &c.IdleTimeout}, {b.MaxSession, &c.MaxSession}} {
		if f.bound > 0 {
			*f.to = f.bound
		}
	}
	for _, l := range []struct {
		allowed []string
		to      *[]string
	}{{b.Trusted, &c.Trusted}, {b.Splice, &c.Splice}} {
		if l.allowed != nil {
			*l.to = slices.DeleteFunc(*l.to, func(h string) bool { return !coveredBy(l.allowed, h) })
		}
	}
	if b.RedirectCDN != nil {
		c.RedirectCDN = slices.DeleteFunc(c.RedirectCDN, func(e string) bool { return !redirectCovered(b.RedirectCDN, e) })
	}
	if b.Internal != nil {
		var ih []InternalHost
		for _, h := range c.Internal {
			i := slices.IndexFunc(b.Internal, func(a InternalHost) bool { return a.Host == h.Host })
			if i < 0 {
				continue
			}
			a := b.Internal[i]
			h.Ports = slices.DeleteFunc(h.Ports, func(port int) bool { return !slices.Contains(a.Ports, port) })
			h.Read = h.Read && a.Read
			if len(h.Ports) > 0 {
				ih = append(ih, h)
			}
		}
		c.Internal = ih
	}
	c.Deny = append(c.Deny, b.Deny...)
	c.ManagedRules = slices.Clone(mg.Rules)
	return Canonical(c)
}

// Keys maps the Diff fields of p and its ceiling to their bound key where
// the two differ: a managed rule's field to "rules".
func (mg *Managed) Keys(p Policy) map[string]string {
	keys := map[string]string{}
	for _, rs := range [][]Rule{mg.Rules, p.ManagedRules} {
		for _, r := range rs {
			keys[managedRuleField+r.ID] = "rules"
		}
	}
	return keys
}

// Bounds of p as lockkit checks them: nil Ceiling when mg bounds nothing.
func (mg *Managed) ManagedBounds(p Policy) managed.Bounds {
	if !mg.Bounded() {
		return managed.Bounds{Tool: product.P.Name, Profile: p.Name}
	}
	return managed.Bounds{Tool: product.P.Name, Profile: p.Name, Ceiling: mg.Ceiling(p), Keys: mg.Keys(p)}
}

// Check lists what of p goes beyond mg's bounds.
func (mg *Managed) Check(p Policy) []managed.Violation {
	if mg == nil {
		return nil
	}
	return managed.Check(p, mg.ManagedBounds(p))
}

// checkDefaults refuses a default beyond the bounds: a policy of the
// defaults alone, its other fields at their ceiling, is checked.
func (mg *Managed) checkDefaults() error {
	b, d := mg.Bounds, mg.defaults
	p := Policy{Name: "defaults", Production: b.Production, Mode: b.Mode, Heuristics: b.Heuristics,
		BufferLimit: b.BufferLimit, ConnectGrant: b.ConnectGrant, IdleTimeout: b.IdleTimeout, MaxSession: b.MaxSession,
		Deny: slices.Clone(b.Deny), ManagedRules: slices.Clone(mg.Rules)}
	if d.Production != nil {
		p.Production = *d.Production
	}
	if d.Mode != nil {
		p.Mode = *d.Mode
	}
	if d.Heuristics != nil {
		p.Heuristics = *d.Heuristics
	}
	var err error
	if d.BufferLimit != nil {
		if p.BufferLimit, err = sizeOr("buffer_limit", *d.BufferLimit, 0); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		key string
		v   *string
		to  *int64
	}{{"hold", d.Hold, &p.Hold}, {"connect_grant", d.ConnectGrant, &p.ConnectGrant}, {"idle_timeout", d.IdleTimeout, &p.IdleTimeout}, {"max_session", d.MaxSession, &p.MaxSession}} {
		if f.v != nil {
			if *f.to, err = secondsOr(f.key, *f.v, 0); err != nil {
				return err
			}
		}
	}
	switch {
	case d.Mode != nil && *d.Mode != ModeEnforce && *d.Mode != ModeShadow:
		return fmt.Errorf("mode must be %q or %q", ModeEnforce, ModeShadow)
	case d.Heuristics != nil && *d.Heuristics != ModeEnforce && *d.Heuristics != ModeShadow && *d.Heuristics != ModeOff:
		return fmt.Errorf("heuristics must be %q, %q or %q", ModeEnforce, ModeShadow, ModeOff)
	case p.Hold > 300:
		return errors.New("hold must be at most 5m (the console's approval timeout)")
	}
	p = Canonical(p)
	if vs := mg.Check(p); len(vs) > 0 {
		return errors.New("beyond the bounds: " + beyond(vs[0]))
	}
	return nil
}

// beyond is a violation without the "blocked by company policy: " of its
// String, for a load error that wraps it.
func beyond(v managed.Violation) string {
	return strings.TrimPrefix(v.String(), "blocked by company policy: ")
}

// ProfilesManaged lists the profiles a console may serve from the config
// file data under mg: the file's and the managed ones, sorted.
func ProfilesManaged(data []byte, name string, mg *Managed) ([]string, error) {
	names, err := Profiles(data, name)
	if err != nil {
		return nil, err
	}
	return kconfig.SortedSet(append(names, mg.ProfileNames()...)), nil
}

// apply fills the keys of r that set reports unset with the defaults.
func (d rawDefaults) apply(r *raw, set func(key string) bool) {
	if d.Production != nil && !set("production") {
		r.Production = *d.Production
	}
	for _, f := range []struct {
		key string
		v   *string
		to  *string
	}{
		{"mode", d.Mode, &r.Mode}, {"heuristics", d.Heuristics, &r.Heuristics}, {"buffer_limit", d.BufferLimit, &r.BufferLimit},
		{"hold", d.Hold, &r.Hold}, {"connect_grant", d.ConnectGrant, &r.ConnectGrant},
		{"idle_timeout", d.IdleTimeout, &r.IdleTimeout}, {"max_session", d.MaxSession, &r.MaxSession},
	} {
		if f.v != nil && !set(f.key) {
			*f.to = *f.v
		}
	}
}

// boundsFromRaw checks [lockhttp.bounds]. Its errors name a key and an
// entry's place, never a value.
func boundsFromRaw(rb rawBounds) (Bounds, []Rule, error) {
	var b Bounds
	if rb.Production != nil {
		if !*rb.Production {
			return b, nil, errors.New("production: the only bound is true")
		}
		b.Production = true
	}
	if rb.Mode != "" && rb.Mode != ModeEnforce {
		return b, nil, fmt.Errorf("mode: the only bound is %q", ModeEnforce)
	}
	b.Mode = rb.Mode
	if rb.Heuristics != "" && rb.Heuristics != ModeShadow && rb.Heuristics != ModeEnforce {
		return b, nil, fmt.Errorf("heuristics: must be %q or %q", ModeShadow, ModeEnforce)
	}
	b.Heuristics = rb.Heuristics
	var err error
	if b.BufferLimit, err = sizeOr("buffer_limit", rb.BufferLimit, 0); err != nil {
		return b, nil, err
	}
	for _, d := range []struct {
		key string
		v   string
		to  *int64
	}{{"connect_grant", rb.ConnectGrant, &b.ConnectGrant}, {"idle_timeout", rb.IdleTimeout, &b.IdleTimeout}, {"max_session", rb.MaxSession, &b.MaxSession}} {
		if *d.to, err = secondsOr(d.key, d.v, 0); err != nil {
			return b, nil, err
		}
	}
	for _, l := range []struct {
		key string
		in  *[]string
		to  *[]string
	}{{"trusted", rb.Trusted, &b.Trusted}, {"splice", rb.Splice, &b.Splice}, {"deny", &rb.Deny, &b.Deny}} {
		if l.in == nil {
			continue
		}
		out := []string{}
		for i, h := range *l.in {
			c, err := CheckHostPattern(entry(l.key, i), h, false)
			if err != nil {
				return b, nil, err
			}
			out = append(out, c)
		}
		*l.to = kconfig.SortedSet(out)
	}
	if len(b.Deny) == 0 {
		b.Deny = nil
	}
	if rb.RedirectCDN != nil {
		b.RedirectCDN = []string{}
		for i, e := range *rb.RedirectCDN {
			c, err := redirectFromRaw(entry("redirect_cdn", i), e)
			if err != nil {
				return b, nil, err
			}
			b.RedirectCDN = append(b.RedirectCDN, c)
		}
	}
	if rb.Internal != nil {
		b.Internal = []InternalHost{}
		for i, ih := range *rb.Internal {
			h, err := internalFromRaw(entry("internal_hosts", i), ih)
			if err != nil {
				return b, nil, err
			}
			b.Internal = append(b.Internal, h)
		}
	}
	var rules []Rule
	seen := map[string]int{}
	for i, rr := range rb.Rules {
		key := entry("rules", i)
		rule, err := ruleFromRaw(key, rr)
		if err != nil {
			return b, nil, err
		}
		if rule.Verdict != VerdictDeny && rule.Verdict != VerdictAsk {
			return b, nil, fmt.Errorf("%s: verdict must be deny or ask: a managed rule only tightens", key)
		}
		if j, dup := seen[rule.ID]; dup {
			return b, nil, fmt.Errorf("%s: id is already used by %s", key, entry("rules", j))
		}
		seen[rule.ID] = i
		rules = append(rules, rule)
	}
	return b, canonicalRules(rules), nil
}

// coveredBy reports whether every host h matches is matched by one of
// the allowed patterns: h itself, or a "*.domain" it is under.
func coveredBy(allowed []string, h string) bool {
	for _, a := range allowed {
		if a == h || (strings.HasPrefix(a, "*.") && strings.HasSuffix(h, a[1:])) {
			return true
		}
	}
	return false
}

// redirectCovered reports whether the "origin>cdn" entry e is within one
// allowed entry.
func redirectCovered(allowed []string, e string) bool {
	from, to, _ := strings.Cut(e, ">")
	for _, a := range allowed {
		af, at, _ := strings.Cut(a, ">")
		if coveredBy([]string{af}, from) && coveredBy([]string{at}, to) {
			return true
		}
	}
	return false
}

// diffManagedRules is the Diff of the managed rules: removing or changing
// one loosens, whatever the change, since only the company's file may.
func diffManagedRules(old, cur []Rule) []kconfig.Change {
	var out []kconfig.Change
	byID := map[string]Rule{}
	for _, r := range cur {
		byID[r.ID] = r
	}
	oldIDs := map[string]bool{}
	for _, o := range old {
		oldIDs[o.ID] = true
		r, ok := byID[o.ID]
		switch {
		case !ok:
			out = append(out, kconfig.Change{Field: managedRuleField + o.ID, Old: o.String(), Loosens: true})
		case o.String() != r.String() || o.Note != r.Note:
			out = append(out, kconfig.Change{Field: managedRuleField + o.ID, Old: o.String(), New: r.String(), Loosens: true})
		}
	}
	for _, r := range cur {
		if !oldIDs[r.ID] {
			out = append(out, kconfig.Change{Field: managedRuleField + r.ID, New: r.String()})
		}
	}
	return out
}

// DescribeBounds is the bounds and rules of mg, one line each, for
// `lockhttp managed show`.
func (mg *Managed) DescribeBounds() []string {
	b := mg.Bounds
	var out []string
	add := func(k, v string) { out = append(out, k+" = "+v) }
	if b.Production {
		add("production", "true")
	}
	if b.Mode != "" {
		add("mode", b.Mode)
	}
	if b.Heuristics != "" {
		add("heuristics", b.Heuristics)
	}
	if b.BufferLimit > 0 {
		add("buffer_limit", FormatSize(b.BufferLimit))
	}
	for _, d := range []struct {
		k string
		v int64
	}{{"connect_grant", b.ConnectGrant}, {"idle_timeout", b.IdleTimeout}, {"max_session", b.MaxSession}} {
		if d.v > 0 {
			add(d.k, secs(d.v))
		}
	}
	for _, l := range []struct {
		k string
		v []string
	}{{"trusted", b.Trusted}, {"splice", b.Splice}, {"redirect_cdn", b.RedirectCDN}} {
		if l.v != nil {
			add(l.k, list(l.v)+" (allowed)")
		}
	}
	if b.Internal != nil {
		var hs []string
		for _, h := range b.Internal {
			hs = append(hs, ihText(h))
		}
		add("internal_hosts", list(hs)+" (allowed)")
	}
	if len(b.Deny) > 0 {
		add("deny", list(b.Deny)+" (required)")
	}
	for _, r := range mg.Rules {
		out = append(out, "rule "+r.ID+": "+r.String())
	}
	return out
}

// DescribeDefaults is [lockhttp.defaults], one line per key set.
func (mg *Managed) DescribeDefaults() []string {
	d := mg.defaults
	var out []string
	if d.Production != nil {
		out = append(out, "production = "+strconv.FormatBool(*d.Production))
	}
	for _, f := range []struct {
		k string
		v *string
	}{{"mode", d.Mode}, {"heuristics", d.Heuristics}, {"buffer_limit", d.BufferLimit}, {"hold", d.Hold},
		{"connect_grant", d.ConnectGrant}, {"idle_timeout", d.IdleTimeout}, {"max_session", d.MaxSession}} {
		if f.v != nil {
			out = append(out, f.k+" = "+*f.v)
		}
	}
	return out
}

func ihText(h InternalHost) string {
	ports := make([]string, len(h.Ports))
	for i, port := range h.Ports {
		ports[i] = strconv.Itoa(port)
	}
	mode := "ask"
	if h.Read {
		mode = "read"
	}
	return h.Host + ":" + strings.Join(ports, ",") + " " + mode
}
