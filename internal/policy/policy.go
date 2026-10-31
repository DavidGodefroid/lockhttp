// Package policy is lockhttp's policy: the profile the human writes in the
// console account's config file, in canonical form. The console approves
// it (lockkit's "the AI tightens, the human loosens" review) and serves it
// to the gate; the gate never reads a policy file.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"

	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// Modes of the policy and of the heuristics.
const (
	// ModeEnforce applies every verdict.
	ModeEnforce = "enforce"
	// ModeShadow logs what would have asked or been denied and lets it
	// pass; the floor and secret matches stay enforced.
	ModeShadow = "shadow"
	// ModeOff (heuristics only) computes no score.
	ModeOff = "off"
)

// Verdicts of a rule.
const (
	VerdictDeny = "deny"
	VerdictAsk  = "ask"
	// VerdictAuto asks without NeverAuto: auto mode may answer it.
	VerdictAuto = "auto"
	VerdictFree = "free"
)

// Defaults (decisions D5 and the connect grant).
const (
	DefaultBufferLimit  = 10 << 20
	DefaultHold         = 60
	DefaultConnectGrant = 600
	DefaultIdle         = 24 * 3600
	DefaultMaxSession   = 24 * 3600
)

// Policy is one profile in canonical form: sorted lists, defaults applied,
// durations in seconds. Its JSON is what the console fingerprints and
// stores as the approved policy, and what the gate receives.
type Policy struct {
	Name       string `json:"name"`
	Production bool   `json:"production"`
	Mode       string `json:"mode"`
	Heuristics string `json:"heuristics"`
	// BufferLimit is the largest body the gate holds for a human (bytes).
	BufferLimit int64 `json:"buffer_limit"`
	// Hold is how long the gate holds a request for the human (seconds).
	Hold int64 `json:"hold"`
	// ConnectGrant is how long an approved CONNECT opens its host for the
	// container (seconds).
	ConnectGrant int64 `json:"connect_grant"`
	IdleTimeout  int64 `json:"idle_timeout"`
	MaxSession   int64 `json:"max_session"`
	// Trusted hosts are free for reads (GET, HEAD, OPTIONS without body).
	Trusted []string `json:"trusted"`
	// Splice hosts are never decrypted: decided at the domain.
	Splice []string `json:"splice"`
	// Deny hosts are always refused.
	Deny []string `json:"deny"`
	// RedirectCDN lists "origin>cdn": a 3xx from origin to cdn lets the
	// same container GET the exact target once, within 60 s.
	RedirectCDN []string       `json:"redirect_cdn"`
	Internal    []InternalHost `json:"internal_hosts"`
	Rules       []Rule         `json:"rules"`
}

// InternalHost is a host of the user's internal-hosts list: it may resolve
// to a private address, on the ports it declares.
type InternalHost struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
	// Read makes reads free; otherwise every request asks.
	Read bool `json:"read"`
}

// Rule is one policy rule. It applies to every container or to one,
// never to an agent: an agent name is declarative.
type Rule struct {
	ID        string   `json:"id"`
	Container string   `json:"container,omitempty"`
	Host      string   `json:"host"`
	Methods   []string `json:"methods"`
	// Path is an exact path, or a prefix when it ends with "*"; "" is any.
	Path    string `json:"path,omitempty"`
	Verdict string `json:"verdict"`
	// MaxBody bounds the body of a matching request (bytes, 0 = the
	// buffer limit).
	MaxBody int64 `json:"max_body,omitempty"`
	// Expires is the last day (UTC) the rule applies, "" for never.
	Expires string `json:"expires,omitempty"`
	Note    string `json:"note,omitempty"`
}

// raw is the TOML shape of a profile.
type raw struct {
	Production   bool      `toml:"production"`
	Mode         string    `toml:"mode"`
	Heuristics   string    `toml:"heuristics"`
	BufferLimit  string    `toml:"buffer_limit"`
	Hold         string    `toml:"hold"`
	ConnectGrant string    `toml:"connect_grant"`
	IdleTimeout  string    `toml:"idle_timeout"`
	MaxSession   string    `toml:"max_session"`
	Trusted      []string  `toml:"trusted"`
	Splice       []string  `toml:"splice"`
	Deny         []string  `toml:"deny"`
	RedirectCDN  []string  `toml:"redirect_cdn"`
	Internal     []rawIH   `toml:"internal_hosts"`
	Rules        []rawRule `toml:"rules"`
}

type rawIH struct {
	Host  string `toml:"host"`
	Ports []int  `toml:"ports"`
	Read  bool   `toml:"read"`
}

type rawRule struct {
	ID        string   `toml:"id"`
	Container string   `toml:"container"`
	Agent     string   `toml:"agent"`
	Host      string   `toml:"host"`
	Methods   []string `toml:"methods"`
	Path      string   `toml:"path"`
	Verdict   string   `toml:"verdict"`
	MaxBody   string   `toml:"max_body"`
	Expires   string   `toml:"expires"`
	Note      string   `toml:"note"`
}

type file struct {
	Profiles map[string]raw `toml:"profiles"`
}

// Parse decodes the config file data and returns profile in canonical
// form. Any unknown key, any key that looks like a secret, and any rule
// that would let auto mode answer a forbidden class is refused.
func Parse(data []byte, name, profile string) (Policy, error) {
	var f file
	if _, err := kconfig.Decode(product.P, data, name, &f); err != nil {
		return Policy{}, err
	}
	r, ok := f.Profiles[profile]
	if !ok {
		return Policy{}, fmt.Errorf("%s: no profile %q", name, profile)
	}
	p, err := fromRaw(profile, r)
	if err != nil {
		return Policy{}, fmt.Errorf("%s: profile %s: %w", name, profile, err)
	}
	return p, nil
}

// Profiles lists the profile names of a config file.
func Profiles(data []byte, name string) ([]string, error) {
	var f file
	if _, err := kconfig.Decode(product.P, data, name, &f); err != nil {
		return nil, err
	}
	var out []string
	for k := range f.Profiles {
		out = append(out, k)
	}
	slices.Sort(out)
	return out, nil
}

func fromRaw(name string, r raw) (Policy, error) {
	if err := kconfig.CheckProfileName(name, r.Production); err != nil {
		return Policy{}, err
	}
	p := Policy{Name: name, Production: r.Production, Mode: r.Mode, Heuristics: r.Heuristics}
	if p.Mode == "" {
		p.Mode = ModeEnforce
	}
	if p.Mode != ModeEnforce && p.Mode != ModeShadow {
		return Policy{}, fmt.Errorf("mode must be %q or %q", ModeEnforce, ModeShadow)
	}
	if p.Heuristics == "" {
		p.Heuristics = ModeShadow
	}
	if p.Heuristics != ModeEnforce && p.Heuristics != ModeShadow && p.Heuristics != ModeOff {
		return Policy{}, fmt.Errorf("heuristics must be %q, %q or %q", ModeEnforce, ModeShadow, ModeOff)
	}
	var err error
	if p.BufferLimit, err = sizeOr("buffer_limit", r.BufferLimit, DefaultBufferLimit); err != nil {
		return Policy{}, err
	}
	for _, d := range []struct {
		key string
		v   string
		def int64
		to  *int64
	}{
		{"hold", r.Hold, DefaultHold, &p.Hold},
		{"connect_grant", r.ConnectGrant, DefaultConnectGrant, &p.ConnectGrant},
		{"idle_timeout", r.IdleTimeout, DefaultIdle, &p.IdleTimeout},
		{"max_session", r.MaxSession, DefaultMaxSession, &p.MaxSession},
	} {
		if *d.to, err = secondsOr(d.key, d.v, d.def); err != nil {
			return Policy{}, err
		}
	}
	if p.Hold > 300 {
		return Policy{}, errors.New("hold must be at most 5m (the console's approval timeout)")
	}
	for _, l := range []struct {
		key string
		in  []string
		to  *[]string
	}{{"trusted", r.Trusted, &p.Trusted}, {"splice", r.Splice, &p.Splice}, {"deny", r.Deny, &p.Deny}} {
		for i, h := range l.in {
			c, err := CheckHostPattern(entry(l.key, i), h, false)
			if err != nil {
				return Policy{}, err
			}
			*l.to = append(*l.to, c)
		}
	}
	for i, e := range r.RedirectCDN {
		key := entry("redirect_cdn", i)
		from, to, ok := strings.Cut(e, ">")
		if !ok {
			return Policy{}, fmt.Errorf(`%s: entries are "origin>cdn"`, key)
		}
		f, err := CheckHostPattern(key+" origin", strings.TrimSpace(from), false)
		if err != nil {
			return Policy{}, err
		}
		t, err := CheckHostPattern(key+" cdn", strings.TrimSpace(to), false)
		if err != nil {
			return Policy{}, err
		}
		p.RedirectCDN = append(p.RedirectCDN, f+">"+t)
	}
	for i, ih := range r.Internal {
		key := entry("internal_hosts", i)
		h, err := CheckHostPattern(key+" host", ih.Host, true)
		if err != nil {
			return Policy{}, err
		}
		if strings.HasPrefix(h, "*.") {
			return Policy{}, fmt.Errorf("%s: name an exact host, not a pattern", key)
		}
		if len(ih.Ports) == 0 {
			return Policy{}, fmt.Errorf("%s: list its ports", key)
		}
		for _, port := range ih.Ports {
			if port < 1 || port > 65535 {
				return Policy{}, fmt.Errorf("%s: ports are 1 to 65535", key)
			}
		}
		p.Internal = append(p.Internal, InternalHost{Host: h, Ports: ih.Ports, Read: ih.Read})
	}
	// Errors name a rule by its place in the file, never by its id: an id
	// is a value the human typed (a pasted secret must not come back).
	seen := map[string]int{}
	for i, rr := range r.Rules {
		key := entry("rules", i)
		rule, err := ruleFromRaw(key, rr)
		if err != nil {
			return Policy{}, err
		}
		if j, dup := seen[rule.ID]; dup {
			return Policy{}, fmt.Errorf("%s: id is already used by %s", key, entry("rules", j))
		}
		seen[rule.ID] = i
		p.Rules = append(p.Rules, rule)
	}
	p = Canonical(p)
	for _, rule := range p.Rules {
		if rule.Verdict == VerdictAuto {
			if why := p.AutoForbidden(rule); why != "" {
				return Policy{}, fmt.Errorf("%s: verdict auto is not allowed: %s", entry("rules", seen[rule.ID]), why)
			}
		}
	}
	return p, nil
}

var (
	ruleIDRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	methodRe    = regexp.MustCompile(`^[A-Z]{1,16}$`)
	containerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	dateRe      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// entry names the i-th (0-based) entry of a list key for an error: by its
// place in the file, 1-based, never by its value.
func entry(key string, i int) string { return fmt.Sprintf("%s entry %d", key, i+1) }

// ruleFromRaw checks one rule; its errors start with key (the rule's
// place in the file) and never repeat a value of the rule.
func ruleFromRaw(key string, rr rawRule) (Rule, error) {
	if !ruleIDRe.MatchString(rr.ID) {
		return Rule{}, fmt.Errorf("%s: id: use 1 to 64 letters, digits, '_', '-' or '.', starting with a letter or digit", key)
	}
	if rr.Agent != "" {
		return Rule{}, fmt.Errorf("%s: rules apply to a container or to all, never to an agent (an agent name is declarative)", key)
	}
	r := Rule{ID: rr.ID, Container: rr.Container, Path: rr.Path, Verdict: rr.Verdict, Expires: rr.Expires, Note: rr.Note}
	if r.Container != "" && !containerRe.MatchString(r.Container) {
		return Rule{}, fmt.Errorf("%s: invalid container", key)
	}
	if strings.TrimSpace(rr.Host) == "*" {
		r.Host = "*"
	} else {
		h, err := CheckHostPattern(key+" host", rr.Host, false)
		if err != nil {
			return Rule{}, err
		}
		r.Host = h
	}
	switch r.Verdict {
	case VerdictDeny, VerdictAsk, VerdictAuto, VerdictFree:
	default:
		return Rule{}, fmt.Errorf("%s: verdict must be deny, ask, auto or free", key)
	}
	for _, m := range rr.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !methodRe.MatchString(m) {
			return Rule{}, fmt.Errorf("%s: invalid method", key)
		}
		r.Methods = append(r.Methods, m)
	}
	if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
		return Rule{}, fmt.Errorf("%s: path must start with /", key)
	}
	for k, v := range map[string]string{"path": r.Path, "note": r.Note} {
		if err := kconfig.CheckValue(product.P, key+" "+k, v); err != nil {
			return Rule{}, err
		}
	}
	if r.Expires != "" {
		if !dateRe.MatchString(r.Expires) {
			return Rule{}, fmt.Errorf("%s: expires must be YYYY-MM-DD", key)
		}
		if _, err := time.Parse(time.DateOnly, r.Expires); err != nil {
			return Rule{}, fmt.Errorf("%s: expires must be YYYY-MM-DD", key)
		}
	}
	if rr.MaxBody != "" {
		n, err := ParseSize(rr.MaxBody)
		if err != nil {
			return Rule{}, fmt.Errorf("%s: max_body: %w", key, err)
		}
		r.MaxBody = n
	}
	return r, nil
}

// Canonical sorts p's lists and removes duplicates.
func Canonical(p Policy) Policy {
	p.Trusted = kconfig.SortedSet(p.Trusted)
	p.Splice = kconfig.SortedSet(p.Splice)
	p.Deny = kconfig.SortedSet(p.Deny)
	p.RedirectCDN = kconfig.SortedSet(p.RedirectCDN)
	ih := make([]InternalHost, 0, len(p.Internal))
	for _, h := range p.Internal {
		h.Ports = slices.Clone(h.Ports)
		slices.Sort(h.Ports)
		h.Ports = slices.Compact(h.Ports)
		ih = append(ih, h)
	}
	slices.SortFunc(ih, func(a, b InternalHost) int { return strings.Compare(a.Host, b.Host) })
	p.Internal = ih
	rules := make([]Rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		r.Methods = kconfig.SortedSet(r.Methods)
		rules = append(rules, r)
	}
	slices.SortFunc(rules, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	p.Rules = rules
	return p
}

// Clone returns a deep copy of p.
func (p Policy) Clone() Policy {
	q := p
	q.Trusted = slices.Clone(p.Trusted)
	q.Splice = slices.Clone(p.Splice)
	q.Deny = slices.Clone(p.Deny)
	q.RedirectCDN = slices.Clone(p.RedirectCDN)
	q.Internal = nil
	for _, h := range p.Internal {
		h.Ports = slices.Clone(h.Ports)
		q.Internal = append(q.Internal, h)
	}
	q.Rules = nil
	for _, r := range p.Rules {
		r.Methods = slices.Clone(r.Methods)
		q.Rules = append(q.Rules, r)
	}
	return q
}

// Profile implements console.Policy: the gate needs no secret.
func (p Policy) Profile() console.Profile {
	return console.Profile{
		Name: p.Name, Production: p.Production, Where: "lockhttp gate",
		Credentials: console.CredentialsNone,
		IdleTimeout: time.Duration(p.IdleTimeout) * time.Second,
		MaxSession:  time.Duration(p.MaxSession) * time.Second,
	}
}

// Fingerprint is the canonical hash of p, as the console stores it.
func (p Policy) Fingerprint() string { return "sha256:" + kconfig.Fingerprint(p) }

// Trusts reports whether host is in the trusted list.
func (p Policy) Trusts(host string) bool { return matchAny(p.Trusted, host) }

// Spliced reports whether host is in the splice list.
func (p Policy) Spliced(host string) bool { return matchAny(p.Splice, host) }

// Denied reports whether host is in the deny list.
func (p Policy) Denied(host string) bool { return matchAny(p.Deny, host) }

// InternalHost returns the internal host entry of host.
func (p Policy) InternalHost(host string) (InternalHost, bool) {
	host = normHost(host)
	for _, h := range p.Internal {
		if h.Host == host {
			return h, true
		}
	}
	return InternalHost{}, false
}

// CDNFor reports whether a redirect from origin to target is listed.
func (p Policy) CDNFor(origin, target string) bool {
	for _, e := range append(slices.Clone(DefaultRedirectCDN), p.RedirectCDN...) {
		from, to, _ := strings.Cut(e, ">")
		if HostMatch(from, origin) && HostMatch(to, target) {
			return true
		}
	}
	return false
}

func matchAny(pats []string, host string) bool {
	for _, pat := range pats {
		if HostMatch(pat, host) {
			return true
		}
	}
	return false
}

// Active reports whether r applies at now (its expiry day included, UTC).
func (r Rule) Active(now time.Time) bool {
	if r.Expires == "" {
		return true
	}
	end, err := time.Parse(time.DateOnly, r.Expires)
	if err != nil {
		return false
	}
	return now.UTC().Before(end.Add(24 * time.Hour))
}

// MatchesPath reports whether path is covered by r.Path.
func (r Rule) MatchesPath(path string) bool {
	switch {
	case r.Path == "":
		return true
	case strings.HasSuffix(r.Path, "*"):
		return strings.HasPrefix(path, strings.TrimSuffix(r.Path, "*"))
	default:
		return path == r.Path
	}
}

// MatchesMethod reports whether method is covered by r.Methods (empty:
// every method).
func (r Rule) MatchesMethod(method string) bool {
	return len(r.Methods) == 0 || slices.Contains(r.Methods, method)
}

// HostMatch matches a host against a pattern: an exact host, "*.domain"
// (any subdomain, not the domain itself) or "*" (any host).
func HostMatch(pat, host string) bool {
	host = normHost(host)
	switch {
	case pat == "*":
		return host != ""
	case strings.HasPrefix(pat, "*."):
		return strings.HasSuffix(host, pat[1:])
	default:
		return host == pat
	}
}

func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// CheckHostPattern validates and normalises a host or "*.domain" pattern.
// A single-label host is accepted only when single is set (internal
// hosts); IP literals never are. Its errors name key, never h: a host is
// a value the human typed.
func CheckHostPattern(key, h string, single bool) (string, error) {
	h = normHost(strings.TrimSpace(h))
	if err := kconfig.CheckValue(product.P, key, h); err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return "", fmt.Errorf("%s: an IP literal: name hosts", key)
	}
	name := strings.TrimPrefix(h, "*.")
	labels := strings.Split(name, ".")
	if len(labels) < 2 && (!single || strings.HasPrefix(h, "*.")) {
		return "", fmt.Errorf("%s: not a full host name (two labels or more)", key)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("%s: not a valid host name (DNS labels of letters, digits and '-', or \"*.domain\")", key)
		}
	}
	return h, nil
}

// ParseSize reads "10MiB", "256KiB", "1GiB", "512B" or a plain number of
// bytes.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.m
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > (1<<40)/mult {
		return 0, errors.New(`invalid size: use a number with B, KiB, MiB or GiB ("10MiB")`)
	}
	return n * mult, nil
}

func sizeOr(key, v string, def int64) (int64, error) {
	if v == "" {
		return def, nil
	}
	n, err := ParseSize(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("%s: must be more than 0", key)
	}
	return n, nil
}

func secondsOr(key, v string, def int64) (int64, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("%s: invalid duration (\"60s\", \"10m\", \"24h\")", key)
	}
	return int64(d / time.Second), nil
}

// FormatSize prints n bytes for a human.
func FormatSize(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
