package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

var verdictRank = map[string]int{VerdictDeny: 0, VerdictAsk: 1, VerdictAuto: 2, VerdictFree: 3}

var heuristicsRank = map[string]int{ModeOff: 0, ModeShadow: 1, ModeEnforce: 2}

// Diff implements config.Policy: what changed since approved, each change
// marked Loosens when it widens what passes without a human.
func (p Policy) Diff(approved kconfig.Policy) []kconfig.Change {
	a, ok := approved.(Policy)
	if !ok {
		if ap, ok2 := approved.(*Policy); ok2 && ap != nil {
			a = *ap
		} else {
			return []kconfig.Change{{Field: "policy", New: "unreadable approved policy", Loosens: true}}
		}
	}
	var out []kconfig.Change
	add := func(field, o, n string, loosens bool) {
		out = append(out, kconfig.Change{Field: field, Old: o, New: n, Loosens: loosens})
	}
	if a.Production != p.Production {
		add("production", strconv.FormatBool(a.Production), strconv.FormatBool(p.Production), !p.Production)
	}
	if a.Mode != p.Mode {
		add("mode", a.Mode, p.Mode, p.Mode == ModeShadow)
	}
	if a.Heuristics != p.Heuristics {
		add("heuristics", a.Heuristics, p.Heuristics, heuristicsRank[p.Heuristics] < heuristicsRank[a.Heuristics])
	}
	if a.BufferLimit != p.BufferLimit {
		add("buffer_limit", FormatSize(a.BufferLimit), FormatSize(p.BufferLimit), kconfig.LooserLimit(a.BufferLimit, p.BufferLimit))
	}
	for _, d := range []struct {
		field   string
		old, nw int64
		looser  bool
	}{
		{"hold", a.Hold, p.Hold, false},
		{"connect_grant", a.ConnectGrant, p.ConnectGrant, p.ConnectGrant > a.ConnectGrant},
		{"idle_timeout", a.IdleTimeout, p.IdleTimeout, p.IdleTimeout > a.IdleTimeout},
		{"max_session", a.MaxSession, p.MaxSession, p.MaxSession > a.MaxSession},
	} {
		if d.old != d.nw {
			add(d.field, secs(d.old), secs(d.nw), d.looser)
		}
	}
	out = append(out, kconfig.SetDiff("trusted", a.Trusted, p.Trusted, false)...)
	out = append(out, kconfig.SetDiff("splice", a.Splice, p.Splice, false)...)
	out = append(out, kconfig.SetDiff("deny", a.Deny, p.Deny, true)...)
	out = append(out, kconfig.SetDiff("redirect_cdn", a.RedirectCDN, p.RedirectCDN, false)...)
	out = append(out, kconfig.SetDiff("internal_hosts", ihTexts(a.Internal), ihTexts(p.Internal), false)...)
	out = append(out, diffRules(a.Rules, p.Rules)...)
	return out
}

func secs(s int64) string { return strconv.FormatInt(s, 10) + "s" }

// ihTexts flattens internal hosts into one text per host, port and mode,
// so that an added port or a read flag is an addition (a loosening).
func ihTexts(hs []InternalHost) []string {
	var out []string
	for _, h := range hs {
		mode := "ask"
		if h.Read {
			mode = "read"
		}
		for _, port := range h.Ports {
			out = append(out, fmt.Sprintf("%s:%d %s", h.Host, port, mode))
			if h.Read {
				// read covers ask: removing read (ask stays) tightens.
				out = append(out, fmt.Sprintf("%s:%d ask", h.Host, port))
			}
		}
	}
	return kconfig.SortedSet(out)
}

func diffRules(old, cur []Rule) []kconfig.Change {
	var out []kconfig.Change
	byID := map[string]Rule{}
	for _, r := range old {
		byID[r.ID] = r
	}
	curIDs := map[string]bool{}
	for _, r := range cur {
		curIDs[r.ID] = true
		o, ok := byID[r.ID]
		if !ok {
			out = append(out, kconfig.Change{Field: "rule " + r.ID, New: r.String(), Loosens: r.Verdict != VerdictDeny})
			continue
		}
		if o.String() != r.String() {
			out = append(out, kconfig.Change{Field: "rule " + r.ID, Old: o.String(), New: r.String(), Loosens: ruleLooser(o, r)})
		}
	}
	for _, r := range old {
		if !curIDs[r.ID] {
			// Removing a rule other than free lets its requests fall back to
			// another rule or the defaults, which may let more through.
			out = append(out, kconfig.Change{Field: "rule " + r.ID, Old: r.String(), Loosens: r.Verdict != VerdictFree})
		}
	}
	return out
}

// ruleLooser reports whether n lets more through than o.
func ruleLooser(o, n Rule) bool {
	widens := verdictRank[n.Verdict] > verdictRank[o.Verdict]
	if n.Verdict != VerdictFree && narrower(o, n) {
		// A deny, ask or auto rule loosens by matching less: what it no
		// longer matches falls back to another rule or the defaults.
		return true
	}
	return widens || narrower(n, o) || (o.Verdict == VerdictDeny && n.Verdict != VerdictDeny)
}

// narrower reports whether rule a matches something b does not (a is not
// within b): another host, container scope widened, methods added, path
// widened, a larger body, a later expiry.
func narrower(a, b Rule) bool {
	if a.Host != b.Host {
		return true
	}
	if b.Container != "" && a.Container != b.Container {
		return true
	}
	if len(b.Methods) > 0 {
		if len(a.Methods) == 0 {
			return true
		}
		for _, m := range a.Methods {
			if !slices.Contains(b.Methods, m) {
				return true
			}
		}
	}
	if a.Path != b.Path && !pathWithin(a.Path, b.Path) {
		return true
	}
	if kconfig.LooserLimit(b.MaxBody, a.MaxBody) {
		return true
	}
	if a.Expires != b.Expires && (a.Expires == "" || (b.Expires != "" && a.Expires > b.Expires)) {
		return true
	}
	return false
}

// pathWithin reports whether every path matched by a is matched by b.
func pathWithin(a, b string) bool {
	switch {
	case b == "":
		return true
	case a == "":
		return false
	case strings.HasSuffix(b, "*"):
		return strings.HasPrefix(strings.TrimSuffix(a, "*"), strings.TrimSuffix(b, "*"))
	default:
		return a == b
	}
}

// String is the one-line form of a rule (for the review and the status).
func (r Rule) String() string {
	var b strings.Builder
	b.WriteString(r.Verdict + " ")
	if len(r.Methods) == 0 {
		b.WriteString("*")
	} else {
		b.WriteString(strings.Join(r.Methods, ","))
	}
	b.WriteString(" " + r.Host + r.Path)
	if r.Container != "" {
		b.WriteString(" container=" + r.Container)
	} else {
		b.WriteString(" all-containers")
	}
	if r.MaxBody > 0 {
		b.WriteString(" max_body=" + FormatSize(r.MaxBody))
	}
	if r.Expires != "" {
		b.WriteString(" expires=" + r.Expires)
	}
	return b.String()
}

// Describe implements config.Policy.
func (p Policy) Describe() []string {
	out := []string{
		fmt.Sprintf("mode %s · heuristics %s · buffer %s · hold %ds · connect grant %ds", p.Mode, p.Heuristics, FormatSize(p.BufferLimit), p.Hold, p.ConnectGrant),
		"trusted reads: " + list(p.Trusted),
		"splice (never decrypted): " + list(p.Splice),
		"deny: " + list(p.Deny),
	}
	if len(p.RedirectCDN) > 0 {
		out = append(out, "redirect CDNs: "+list(p.RedirectCDN))
	}
	for _, h := range p.Internal {
		mode := "ask"
		if h.Read {
			mode = "read"
		}
		ports := make([]string, len(h.Ports))
		for i, port := range h.Ports {
			ports[i] = strconv.Itoa(port)
		}
		out = append(out, fmt.Sprintf("internal host %s ports %s (%s)", h.Host, strings.Join(ports, ","), mode))
	}
	for _, r := range p.Rules {
		out = append(out, "rule "+r.ID+": "+r.String())
	}
	return out
}

func list(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, " ")
}
