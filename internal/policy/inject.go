package policy

import (
	"fmt"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// Inject is one credential injection: the gate adds Header to the
// requests a container sends to Host:Port, after the verdict, with the
// value of the secret named Credential in the gate's secrets file (prefixed
// with Scheme and a space when Scheme is set). The policy names the
// secret, never its value: the value stays in the gate's container and
// never reaches the agent, the console or the hub.
type Inject struct {
	ID string `json:"id"`
	// Container limits the injection to one container ("" for every one).
	Container string `json:"container,omitempty"`
	// Host is an exact host name (an internal host may be single-label).
	Host string `json:"host"`
	Port int    `json:"port"`
	// Header is the header's canonical name ("Authorization").
	Header string `json:"header"`
	// Scheme prefixes the value ("Bearer"), "" for the bare secret.
	Scheme string `json:"scheme,omitempty"`
	// Credential names the value in the gate's secrets file ("secret" is
	// a word config keys may not use).
	Credential string `json:"credential"`
	// Methods limits the injection to these methods (upper case, sorted;
	// empty: every method but TRACE and TRACK, in any case, which the gate
	// refuses).
	Methods []string `json:"methods,omitempty"`
	// Paths limits it to these paths, each exact or a prefix when it ends
	// with "*" (sorted; empty: every path). A path a target may resolve to
	// another one never matches (AmbiguousPath).
	Paths []string `json:"paths,omitempty"`
	Note  string   `json:"note,omitempty"`
}

type rawInject struct {
	ID         string   `toml:"id"`
	Container  string   `toml:"container"`
	Host       string   `toml:"host"`
	Port       int      `toml:"port"`
	Header     string   `toml:"header"`
	Scheme     string   `toml:"scheme"`
	Credential string   `toml:"credential"`
	Methods    []string `toml:"methods"`
	Paths      []string `toml:"paths"`
	Note       string   `toml:"note"`
}

var (
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	schemeRe     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,31}$`)
	credNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	credRunRe    = regexp.MustCompile(`[a-z0-9]{17,}`)
)

// CredentialName reports whether name is a valid name of a secret, in
// the policy and in the gate's secrets file: lower-case letters, digits,
// '_', '-' and '.', at most 32 characters, no run of more than 16 letters
// and digits (a name, not a pasted token).
func CredentialName(name string) bool {
	return credNameRe.MatchString(name) && !credRunRe.MatchString(name)
}

// forbiddenInjectHeaders are headers the gate owns: framing, hop-by-hop,
// the proxy's own and the target's name.
var forbiddenInjectHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true, "Keep-Alive": true,
	"Te": true, "Trailer": true, "Upgrade": true, "Expect": true, "Content-Type": true, "Content-Encoding": true,
	"Proxy-Authorization": true, "Proxy-Authenticate": true, "Proxy-Connection": true, "X-Lea-Source": true,
}

func injectsFromRaw(in []rawInject, p Policy) ([]Inject, error) {
	var out []Inject
	ids := map[string]bool{}
	targets := map[string]string{}
	for _, ri := range in {
		inj, err := injectFromRaw(ri)
		if err != nil {
			return nil, err
		}
		if ids[inj.ID] {
			return nil, fmt.Errorf("inject id %q is used twice", inj.ID)
		}
		ids[inj.ID] = true
		if matchAny(p.Splice, inj.Host) {
			return nil, fmt.Errorf("inject %s: %s is spliced (never decrypted): the gate cannot add a header", inj.ID, inj.Host)
		}
		// Two injections of one header for the same requests would be
		// ambiguous. A container-scoped one beside an all-containers one
		// is not: the container's wins (InjectFor).
		key := inj.Host + ":" + strconv.Itoa(inj.Port) + " " + inj.Header + " " + inj.Container
		if other, dup := targets[key]; dup {
			return nil, fmt.Errorf("inject %s: %s already injects %s on %s:%d", inj.ID, other, inj.Header, inj.Host, inj.Port)
		}
		targets[key] = inj.ID
		out = append(out, inj)
	}
	return out, nil
}

func injectFromRaw(ri rawInject) (Inject, error) {
	if !ruleIDRe.MatchString(ri.ID) {
		return Inject{}, fmt.Errorf("inject id %q: use letters, digits, '_', '-' or '.'", ri.ID)
	}
	inj := Inject{ID: ri.ID, Container: ri.Container, Port: ri.Port, Scheme: ri.Scheme, Credential: ri.Credential, Note: ri.Note}
	if inj.Container != "" && !containerRe.MatchString(inj.Container) {
		return Inject{}, fmt.Errorf("inject %s: invalid container", ri.ID)
	}
	h, err := CheckHostPattern("inject "+ri.ID+" host", ri.Host, true)
	if err != nil {
		return Inject{}, err
	}
	if strings.HasPrefix(h, "*.") || h == "*" {
		return Inject{}, fmt.Errorf("inject %s: name an exact host, not a pattern", ri.ID)
	}
	inj.Host = h
	if inj.Port < 1 || inj.Port > 65535 {
		return Inject{}, fmt.Errorf("inject %s: port is required (1-65535)", ri.ID)
	}
	if !headerNameRe.MatchString(ri.Header) {
		return Inject{}, fmt.Errorf("inject %s: header must be a header name (letters, digits and '-')", ri.ID)
	}
	inj.Header = textproto.CanonicalMIMEHeaderKey(ri.Header)
	if forbiddenInjectHeaders[inj.Header] || strings.HasPrefix(inj.Header, "Proxy-") || strings.HasPrefix(inj.Header, "X-Lockhttp-") {
		return Inject{}, fmt.Errorf("inject %s: the gate owns the header %s", ri.ID, inj.Header)
	}
	if inj.Scheme != "" && !schemeRe.MatchString(inj.Scheme) {
		return Inject{}, fmt.Errorf("inject %s: scheme must be a word (\"Bearer\", \"Token\")", ri.ID)
	}
	if !CredentialName(inj.Credential) {
		return Inject{}, fmt.Errorf("inject %s: credential names a secret of the gate's secrets file (\"ha-token\": lower-case letters, digits, '_', '-' or '.', at most 32), never its value", ri.ID)
	}
	for k, v := range map[string]string{"credential": inj.Credential, "note": inj.Note} {
		if err := kconfig.CheckValue(product.P, "inject "+ri.ID+" "+k, v); err != nil {
			return Inject{}, err
		}
	}
	for _, m := range ri.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !methodRe.MatchString(m) {
			return Inject{}, fmt.Errorf("inject %s: invalid method", ri.ID)
		}
		if m == "TRACE" || m == "TRACK" || m == "CONNECT" {
			// TRACE and TRACK echo the request, its header included.
			return Inject{}, fmt.Errorf("inject %s: the gate never injects into %s", ri.ID, m)
		}
		inj.Methods = append(inj.Methods, m)
	}
	for _, path := range ri.Paths {
		if !strings.HasPrefix(path, "/") {
			return Inject{}, fmt.Errorf("inject %s: a path must start with /", ri.ID)
		}
		if err := kconfig.CheckValue(product.P, "inject "+ri.ID+" path", path); err != nil {
			return Inject{}, err
		}
		inj.Paths = append(inj.Paths, path)
	}
	inj.Methods = kconfig.SortedSet(inj.Methods)
	inj.Paths = kconfig.SortedSet(inj.Paths)
	return inj, nil
}

// String is the one-line form of an injection (for the review): names
// only, never a value.
func (i Inject) String() string {
	s := fmt.Sprintf("%s %s:%d %s", i.ID, i.Host, i.Port, i.Header)
	if i.Scheme != "" {
		s += " " + i.Scheme
	}
	s += " credential=" + i.Credential
	if len(i.Methods) > 0 {
		s += " methods=" + strings.Join(i.Methods, ",")
	}
	if len(i.Paths) > 0 {
		s += " paths=" + strings.Join(i.Paths, ",")
	}
	if i.Container != "" {
		s += " container=" + i.Container
	} else {
		s += " all-containers"
	}
	return s
}

// Applies reports whether i covers a request of container to host:port.
func (i Inject) Applies(container, host string, port int) bool {
	return i.Host == normHost(host) && i.Port == port && (i.Container == "" || i.Container == container)
}

// MatchesRequest reports whether i covers method and path (the escaped
// path, as rules match it). TRACE and TRACK, in any case, never match:
// they echo the request, the injected header included. With paths, a
// path a target may resolve to another one (see AmbiguousPath) never
// matches: "/api/../admin" is not under "/api/*" at the target.
func (i Inject) MatchesRequest(method, path string) bool {
	if strings.EqualFold(method, "TRACE") || strings.EqualFold(method, "TRACK") {
		return false
	}
	if len(i.Methods) > 0 && !slices.Contains(i.Methods, method) {
		return false
	}
	if len(i.Paths) == 0 {
		return true
	}
	if AmbiguousPath(path) {
		return false
	}
	for _, p := range i.Paths {
		if (Rule{Path: p}).MatchesPath(path) {
			return true
		}
	}
	return false
}

// pathDecodeRounds bounds how many times AmbiguousPath decodes a path:
// one still changing after them is ambiguous.
const pathDecodeRounds = 3

// AmbiguousPath reports whether an escaped path may name, at a target,
// another path than its string: a dot segment ("." or "..", also with
// ";" parameters), a backslash, an encoded dot, slash or backslash
// (%2E, %2F, %5C, in any case), an invalid escape, or any of them after
// up to pathDecodeRounds rounds of percent-decoding ("%252e"). A target
// that resolves dot segments or decodes the path would route it outside
// the prefix it matched as a string.
func AmbiguousPath(path string) bool {
	p := path
	for round := 0; round < pathDecodeRounds; round++ {
		if strings.ContainsRune(p, '\\') {
			return true
		}
		for _, seg := range strings.Split(p, "/") {
			seg, _, _ = strings.Cut(seg, ";")
			if seg == "." || seg == ".." {
				return true
			}
		}
		if !strings.Contains(p, "%") {
			return false
		}
		low := strings.ToLower(p)
		if strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") {
			return true
		}
		d, err := url.PathUnescape(p)
		if err != nil {
			return true
		}
		if d == p {
			return false
		}
		p = d
	}
	return true
}

// InjectFor returns the injections that apply to a request of container
// to host:port (any method and path), a container-scoped one before an
// all-containers one of the same header (only the first of each header
// applies).
func (p Policy) InjectFor(container, host string, port int) []Inject {
	return p.injectFor(container, host, port, func(Inject) bool { return true })
}

// InjectForRequest is InjectFor for one method and path: an injection
// whose methods or paths do not name them does not apply (and does not
// hide an all-containers one).
func (p Policy) InjectForRequest(container, host string, port int, method, path string) []Inject {
	return p.injectFor(container, host, port, func(i Inject) bool { return i.MatchesRequest(method, path) })
}

func (p Policy) injectFor(container, host string, port int, keep func(Inject) bool) []Inject {
	var scoped, all []Inject
	for _, i := range p.Inject {
		if !i.Applies(container, host, port) || !keep(i) {
			continue
		}
		if i.Container != "" {
			scoped = append(scoped, i)
		} else {
			all = append(all, i)
		}
	}
	out := scoped
	for _, i := range all {
		dup := false
		for _, s := range scoped {
			dup = dup || s.Header == i.Header
		}
		if !dup {
			out = append(out, i)
		}
	}
	return out
}

// InjectAt returns every injection to host:port, whatever its container,
// methods and paths: each response from that host and port may carry one
// of their credentials (stored by an injected request, served to another
// path or another container).
func (p Policy) InjectAt(host string, port int) []Inject {
	var out []Inject
	for _, i := range p.Inject {
		if i.Host == normHost(host) && i.Port == port {
			out = append(out, i)
		}
	}
	return out
}
