// Package decide is lockhttp's decision engine: one request (a CONNECT
// seen at the domain, or a decrypted or plain HTTP request) and the
// approved policy in, a verdict out: FREE, ASK or DENY. It holds no
// state; the gate's grants and single-use authorisations are checked by
// the gate between Floor and Evaluate.
package decide

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// Verdict is the outcome of a decision.
type Verdict string

// Verdicts.
const (
	Free Verdict = "free"
	Ask  Verdict = "ask"
	Deny Verdict = "deny"
)

// Phase says how much of the request the gate sees.
type Phase string

// Phases.
const (
	// PhaseConnect: a CONNECT, decided at the domain (no decryption, or a
	// spliced host). Approving it opens reads AND writes.
	PhaseConnect Phase = "connect"
	// PhaseHTTP: a plain HTTP request or a decrypted HTTPS one.
	PhaseHTTP Phase = "http"
)

// UploadSize is the body size from which a write counts as an upload.
const UploadSize = 64 << 10

// Request is what the gate knows of a request.
type Request struct {
	Phase     Phase
	Container string
	// Via is direct, keyproxy or nested.
	Via    string
	Method string
	// Host is the target host name (lower case, no port); Port its port.
	Host string
	Port int
	// SNI is the TLS server name the client sent ("" when none or not
	// peeked).
	SNI      string
	Path     string
	RawQuery string
	Header   http.Header
	// BodyLen is the body length, -1 when unknown (chunked); Body the
	// buffered body when the gate holds it (nil otherwise).
	BodyLen int64
	Body    []byte
	// TLS reports a decrypted HTTPS request (PhaseHTTP).
	TLS bool
}

// Decision is the engine's answer.
type Decision struct {
	Verdict Verdict
	// Rule names what decided: a policy rule id, or a built-in
	// ("floor:ip-literal", "trusted", "claude:messages", "default:write").
	Rule string
	// Code is the refusal code of a DENY (and of an ASK refused).
	Code   refusal.Code
	Reason string
	// Warnings are shown in red on the approval screen and audited.
	Warnings []string
	// NeverAuto: auto mode may not answer this ASK.
	NeverAuto bool
	// Red frames the approval screen in red.
	Red bool
	// Score is the exfiltration score; Shadow is what the policy would
	// have decided had it been enforced ("ask", "deny"), when shadow
	// mode let the request pass.
	Score  int
	Shadow Verdict
	// Class names the request's class (read, write, upload, messaging,
	// publish, receive-pack, websocket, claude, internal, connect).
	Class string
}

func deny(rule string, code refusal.Code, reason string) Decision {
	return Decision{Verdict: Deny, Rule: rule, Code: code, Reason: reason}
}

// Floor applies the hard floor: what no policy loosens. It returns false
// when the request passes the floor.
func Floor(p *policy.Policy, r Request) (Decision, bool) {
	host := r.Host
	if host == "" {
		return deny("floor:no-host", product.CodeFloor, "no target host"), true
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return deny("floor:ip-literal", product.CodeFloor, "IP literal "+host+": name the host"), true
	}
	if isMetadata(host) {
		return deny("floor:metadata", product.CodeFloor, "cloud metadata host "+host), true
	}
	if isDoH(host, r) {
		return deny("floor:doh", product.CodeFloor, "DNS over HTTPS is refused: use the container's resolver"), true
	}
	if r.Phase == PhaseHTTP && r.Method == http.MethodConnect {
		return deny("floor:nested-connect", product.CodeFloor, "CONNECT inside a tunnel"), true
	}
	if r.SNI != "" && !strings.EqualFold(strings.TrimSuffix(r.SNI, "."), host) {
		return deny("floor:sni", product.CodeFloor, fmt.Sprintf("TLS server name %q differs from the CONNECT host %q", r.SNI, host)), true
	}
	if r.Header != nil && strings.EqualFold(r.Header.Get("Upgrade"), "h2c") {
		return deny("floor:h2c", product.CodeFloor, "Upgrade: h2c is refused"), true
	}
	if r.Port != 80 && r.Port != 443 {
		if p != nil {
			if ih, ok := p.InternalHost(host); ok && slices.Contains(ih.Ports, r.Port) {
				return Decision{}, false
			}
		}
		return deny("floor:port", product.CodeFloor, fmt.Sprintf("port %d: only 80 and 443 (and an internal host's declared ports)", r.Port)), true
	}
	if !strings.Contains(host, ".") {
		if p != nil {
			if _, ok := p.InternalHost(host); ok {
				return Decision{}, false
			}
		}
		return deny("floor:single-label", product.CodeFloor, "single-label host "+host+" is not an internal host"), true
	}
	return Decision{}, false
}

var dohHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "*.cloudflare-dns.com", "one.one.one.one",
	"dns.quad9.net", "*.quad9.net", "doh.opendns.com", "*.nextdns.io", "dns.adguard.com",
	"dns.adguard-dns.com", "doh.cleanbrowsing.org", "dns.sb", "doh.dns.sb",
}

func isDoH(host string, r Request) bool {
	if strings.HasPrefix(host, "doh.") || strings.HasPrefix(host, "dns.") {
		return true
	}
	for _, h := range dohHosts {
		if policy.HostMatch(h, host) {
			return true
		}
	}
	if r.Phase == PhaseHTTP {
		if strings.HasSuffix(r.Path, "/dns-query") || strings.HasPrefix(r.Path, "/resolve") && strings.Contains(r.RawQuery, "name=") {
			return true
		}
		if r.Header != nil && strings.Contains(strings.ToLower(r.Header.Get("Content-Type")+r.Header.Get("Accept")), "application/dns-message") {
			return true
		}
	}
	return false
}

func isMetadata(host string) bool {
	switch host {
	case "metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal":
		return true
	}
	return false
}

// Evaluate decides a request that passed the floor and matched no grant.
// p nil means the gate has no approved policy: only the Claude hosts are
// free, everything else asks.
func Evaluate(p *policy.Policy, r Request, now time.Time, creds Credentials) Decision {
	d := evaluate(p, r, now, creds)
	if p != nil && p.Mode == policy.ModeShadow && d.Verdict != Free && !strings.HasPrefix(d.Rule, "floor:") && d.Code != product.CodeSecretEgress {
		d.Shadow, d.Verdict = d.Verdict, Free
	}
	return d
}

func evaluate(p *policy.Policy, r Request, now time.Time, creds Credentials) Decision {
	host := r.Host
	if p != nil && p.Denied(host) {
		return deny("deny-list", product.CodeRule, host+" is on the policy's deny list")
	}
	// Secrets first: a credential outside its host is denied, whatever
	// rule would let the request pass.
	if r.Phase == PhaseHTTP {
		if d, ok := secretCheck(r); ok {
			return d
		}
	}
	// Internal hosts (D-ih): spliced, decided at the domain.
	if p != nil {
		if ih, ok := p.InternalHost(host); ok {
			if ih.Read && (r.Phase == PhaseConnect || isRead(r)) {
				return Decision{Verdict: Free, Rule: "internal:read", Class: "internal"}
			}
			return Decision{Verdict: Ask, Rule: "internal", Class: "internal", NeverAuto: true,
				Warnings: connectWarning(r)}
		}
	}
	score, warns := 0, []string(nil)
	if r.Phase == PhaseHTTP && (p == nil || p.Heuristics != policy.ModeOff) {
		score, warns = Score(r)
	}
	heurHit := score >= ScoreThreshold && p != nil && p.Heuristics == policy.ModeEnforce
	d := evaluateRules(p, r, now, creds)
	d.Score = score
	if heurHit && d.Verdict != Deny {
		d.Verdict, d.NeverAuto, d.Red = Ask, true, true
		d.Code = product.CodeExfilSuspect
		d.Warnings = append(d.Warnings, warns...)
	} else if score >= ScoreThreshold {
		// Shadow: logged with the score, not shown as a block.
		d.Warnings = append(d.Warnings, warns...)
	}
	return d
}

func evaluateRules(p *policy.Policy, r Request, now time.Time, creds Credentials) Decision {
	host := r.Host
	class := classify(r)
	// Rules, most specific first.
	if p != nil {
		if rule, ok := bestRule(p, r, now); ok {
			return fromRule(p, rule, r, class)
		}
	}
	// Claude API and the Anthropic domains.
	if policy.UnderAnthropic(host) {
		return claude(r, creds)
	}
	if r.Phase == PhaseConnect {
		if p != nil && p.Trusts(host) {
			return Decision{Verdict: Free, Rule: "trusted", Class: "connect"}
		}
		return Decision{Verdict: Ask, Rule: "default:unknown-host", Class: "connect", NeverAuto: true, Red: true,
			Code: product.CodeHostUnknown, Warnings: connectWarning(r)}
	}
	return defaults(p, r, class)
}

func connectWarning(r Request) []string {
	if r.Phase != PhaseConnect {
		return nil
	}
	return []string{"opens " + r.Host + " for reads AND writes: the content is not visible (no decryption)"}
}

func defaults(p *policy.Policy, r Request, class string) Decision {
	host := r.Host
	limit := int64(policy.DefaultBufferLimit)
	if p != nil {
		limit = p.BufferLimit
	}
	switch class {
	case "read":
		if p != nil && p.Trusts(host) {
			return Decision{Verdict: Free, Rule: "trusted", Class: class}
		}
		return Decision{Verdict: Ask, Rule: "default:unknown-host", Class: class, NeverAuto: true, Code: product.CodeHostUnknown,
			Warnings: []string{"unknown host " + host}}
	}
	if r.BodyLen > limit {
		return deny("default:body-limit", product.CodeBodyTooLarge, fmt.Sprintf("body of %d bytes exceeds the buffer limit (%s)", r.BodyLen, policy.FormatSize(limit)))
	}
	d := Decision{Verdict: Ask, Rule: "default:" + class, Class: class, NeverAuto: true}
	switch class {
	case "messaging":
		d.Red = true
		d.Warnings = append(d.Warnings, "sends a message on someone's behalf ("+host+")")
	case "publish":
		d.Red = true
		d.Warnings = append(d.Warnings, "publishes to a registry ("+host+")")
	case "receive-pack":
		d.Red = true
		d.Warnings = append(d.Warnings, "git push to "+host)
	case "upload":
		d.Warnings = append(d.Warnings, "upload")
	case "websocket":
		d.Warnings = append(d.Warnings, "opens a WebSocket: the whole session is a write")
	}
	if p != nil && !p.Trusts(host) {
		d.Warnings = append(d.Warnings, "unknown host "+host)
	}
	return d
}

// classify names a request's class.
func classify(r Request) string {
	if r.Phase == PhaseConnect {
		return "connect"
	}
	switch {
	case policy.IsReceivePack(r.Path, r.RawQuery):
		return "receive-pack"
	case r.Header != nil && strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		return "websocket"
	case isRead(r):
		return "read"
	case policy.IsMessaging(r.Host):
		return "messaging"
	case policy.IsPublish(r.Host) && policy.PublishMethods(r.Host, []string{r.Method}):
		return "publish"
	case isUpload(r):
		return "upload"
	}
	return "write"
}

func isRead(r Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return r.BodyLen == 0 || (r.BodyLen < 0 && r.Body == nil && r.Header.Get("Transfer-Encoding") == "")
	}
	return false
}

func isUpload(r Request) bool {
	if r.BodyLen > UploadSize || r.BodyLen < 0 {
		return true
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "multipart/") || strings.HasPrefix(ct, "application/octet-stream") ||
		strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") ||
		strings.Contains(ct, "zip") || strings.Contains(ct, "tar") {
		return true
	}
	return false
}

// bestRule finds the most specific active rule matching r.
func bestRule(p *policy.Policy, r Request, now time.Time) (policy.Rule, bool) {
	var best policy.Rule
	bestScore := -1
	for _, rule := range p.Rules {
		if !rule.Active(now) || !policy.HostMatch(rule.Host, r.Host) {
			continue
		}
		if rule.Container != "" && rule.Container != r.Container {
			continue
		}
		if r.Phase == PhaseConnect {
			// At the domain the method and path are unknown: only a
			// rule without either decides; a narrower rule asks.
			if len(rule.Methods) > 0 || rule.Path != "" {
				continue
			}
		} else if !rule.MatchesMethod(r.Method) || !rule.MatchesPath(r.Path) {
			continue
		}
		if s := specificity(rule); s > bestScore {
			best, bestScore = rule, s
		}
	}
	return best, bestScore >= 0
}

func specificity(r policy.Rule) int {
	s := 0
	if r.Container != "" {
		s += 1000
	}
	switch {
	case r.Host == "*":
	case strings.HasPrefix(r.Host, "*."):
		s += 100 + len(r.Host)
	default:
		s += 400 + len(r.Host)
	}
	switch {
	case r.Path == "":
	case strings.HasSuffix(r.Path, "*"):
		s += 50 + len(r.Path)
	default:
		s += 300
	}
	if len(r.Methods) > 0 {
		s += 10
	}
	return s
}

func fromRule(p *policy.Policy, rule policy.Rule, r Request, class string) Decision {
	d := Decision{Rule: rule.ID, Class: class}
	limit := p.BufferLimit
	if rule.MaxBody > 0 {
		limit = rule.MaxBody
	}
	switch rule.Verdict {
	case policy.VerdictDeny:
		return deny(rule.ID, product.CodeRule, "rule "+rule.ID+" denies it")
	case policy.VerdictFree:
		d.Verdict = Free
	case policy.VerdictAuto:
		d.Verdict = Ask
		// Runtime classes never auto: uploads, messaging, publishing,
		// git push, a spliced host, production.
		d.NeverAuto = p.Production || p.Spliced(r.Host) || p.AutoForbidden(rule) != "" ||
			slices.Contains([]string{"upload", "messaging", "publish", "receive-pack", "websocket", "connect"}, class)
	default:
		d.Verdict, d.NeverAuto = Ask, true
	}
	if r.Phase == PhaseHTTP && r.BodyLen > limit {
		if rule.MaxBody > 0 {
			d.Verdict, d.NeverAuto = Ask, true
			d.Warnings = append(d.Warnings, fmt.Sprintf("body of %d bytes exceeds the rule's max_body (%s)", r.BodyLen, policy.FormatSize(rule.MaxBody)))
		}
		if r.BodyLen > p.BufferLimit && d.Verdict != Free {
			return deny(rule.ID, product.CodeBodyTooLarge, fmt.Sprintf("body of %d bytes exceeds the buffer limit (%s)", r.BodyLen, policy.FormatSize(p.BufferLimit)))
		}
	}
	if r.Phase == PhaseConnect {
		d.Warnings = append(d.Warnings, connectWarning(r)...)
	}
	return d
}
