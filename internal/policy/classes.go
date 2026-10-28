package policy

import (
	"slices"
	"strings"
)

// MessagingHosts send messages on someone's behalf: every write asks, and
// no rule may make them auto.
var MessagingHosts = []string{
	"hooks.slack.com", "slack.com", "*.slack.com",
	"gmail.googleapis.com", "graph.microsoft.com", "outlook.office.com", "outlook.office365.com",
	"discord.com", "discordapp.com", "api.telegram.org", "api.twilio.com",
	"api.sendgrid.com", "api.mailgun.net", "api.postmarkapp.com", "smtp.gmail.com",
	"api.pushover.net", "ntfy.sh", "webhook.site", "*.webhook.office.com",
}

// PublishHosts are package and image registries: a write there publishes.
var PublishHosts = []string{
	"registry.npmjs.org", "upload.pypi.org", "test.pypi.org", "crates.io", "rubygems.org",
	"registry-1.docker.io", "ghcr.io", "quay.io", "*.pkg.dev", "*.azurecr.io",
	"api.nuget.org", "repo.maven.apache.org", "uploads.github.com",
}

// DefaultRedirectCDN are the CDNs an origin's 3xx may send a GET to (the
// exact target, once, within 60 s), whatever the policy adds.
var DefaultRedirectCDN = []string{
	"ghcr.io>pkg-containers.githubusercontent.com",
	"github.com>objects.githubusercontent.com",
	"github.com>release-assets.githubusercontent.com",
	"github.com>codeload.github.com",
	"api.github.com>codeload.github.com",
	"registry-1.docker.io>production.cloudflare.docker.com",
	"proxy.golang.org>storage.googleapis.com",
	"pypi.org>files.pythonhosted.org",
}

// ClaudeHosts are free at the domain in phase 1 (CONNECT): the hosts
// Claude Code reaches. Any other host under the Anthropic domains asks.
var ClaudeHosts = []string{"api.anthropic.com", "claude.ai", "console.anthropic.com", "statsig.anthropic.com"}

// AnthropicDomains are the domains whose other hosts always ask
// (NeverAuto) unless a rule says otherwise.
var AnthropicDomains = []string{"anthropic.com", "claude.ai", "claude.com"}

// IsMessaging reports whether host sends messages.
func IsMessaging(host string) bool { return matchAny(MessagingHosts, host) }

// IsPublish reports whether a write to host publishes a package or image.
func IsPublish(host string) bool { return matchAny(PublishHosts, host) }

// uploadHosts take a publish with a POST.
var uploadHosts = []string{"upload.pypi.org", "test.pypi.org", "uploads.github.com"}

// PublishMethods reports whether methods (empty: all) include one that
// publishes on registry host: PUT, PATCH, DELETE anywhere, and any write
// on an upload host.
func PublishMethods(host string, methods []string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		switch m {
		case "PUT", "PATCH", "DELETE":
			return true
		case "GET", "HEAD", "OPTIONS":
		default:
			if matchAny(uploadHosts, host) {
				return true
			}
		}
	}
	return false
}

// IsReceivePack reports whether path pushes to a git repository.
func IsReceivePack(path, rawQuery string) bool {
	return strings.HasSuffix(path, "/git-receive-pack") || strings.Contains(rawQuery, "service=git-receive-pack")
}

// UnderAnthropic reports whether host is one of the Anthropic domains or
// a subdomain of one.
func UnderAnthropic(host string) bool {
	host = normHost(host)
	for _, d := range AnthropicDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func readOnly(methods []string) bool {
	if len(methods) == 0 {
		return false
	}
	for _, m := range methods {
		if m != "GET" && m != "HEAD" && m != "OPTIONS" {
			return false
		}
	}
	return true
}

// AutoForbidden returns why rule may not have verdict auto in p, or "".
// The classes are those that always need a human: production, all hosts,
// a spliced host, messaging, registry publishing, git-receive-pack. The
// runtime classes (an exfiltration score, a secret, an upload) are checked
// per request.
func (p Policy) AutoForbidden(r Rule) string {
	switch {
	case p.Production:
		return "the profile is production"
	case r.Host == "*":
		return "a rule for every host"
	case strings.HasPrefix(r.Host, "*.") && p.Spliced(strings.TrimPrefix(r.Host, "*.")+".x"),
		!strings.HasPrefix(r.Host, "*.") && p.Spliced(r.Host):
		return "the host is spliced (never decrypted)"
	case IsMessaging(r.Host) || hostPatternOverlaps(r.Host, MessagingHosts):
		return "the host sends messages"
	case (IsPublish(r.Host) || hostPatternOverlaps(r.Host, PublishHosts)) && PublishMethods(r.Host, r.Methods):
		return "a write to a package or image registry publishes"
	case strings.Contains(r.Path, "git-receive-pack"):
		return "git-receive-pack pushes to a repository"
	case r.Path == "" && !readOnly(r.Methods) && isForge(r.Host):
		return "a write to any path of a git forge includes git-receive-pack: set a path"
	}
	return ""
}

func isForge(host string) bool {
	return slices.Contains([]string{"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}, host)
}

// hostPatternOverlaps reports whether a "*.domain" pattern covers one of
// hosts.
func hostPatternOverlaps(pat string, hosts []string) bool {
	if !strings.HasPrefix(pat, "*.") {
		return false
	}
	for _, h := range hosts {
		if HostMatch(pat, strings.TrimPrefix(h, "*.")) || HostMatch(pat, h) {
			return true
		}
	}
	return false
}

// DocsTrusted is the initial trusted read set (decision D8).
var DocsTrusted = []string{
	"go.dev", "pkg.go.dev", "proxy.golang.org", "sum.golang.org", "storage.googleapis.com",
	"docs.python.org", "pypi.org", "files.pythonhosted.org",
	"registry.npmjs.org", "nodejs.org",
	"developer.mozilla.org", "docs.docker.com", "kubernetes.io", "man7.org", "docs.anthropic.com",
	"github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com",
	"raw.githubusercontent.com", "release-assets.githubusercontent.com",
	"crates.io", "static.crates.io", "index.crates.io",
	"deb.debian.org", "security.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
	"dl-cdn.alpinelinux.org",
}

// DefaultConfig is the config file `lockhttp init` writes: the docs set,
// plus imported hosts (lea's LEA_EGRESS_ALLOW: "example.org", or
// ".corp.example" for the domain and its subdomains) as trusted reads.
func DefaultConfig(imports []string) string {
	trusted := slices.Clone(DocsTrusted)
	for _, h := range imports {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if d, ok := strings.CutPrefix(h, "."); ok {
			trusted = append(trusted, d, "*."+d)
			continue
		}
		trusted = append(trusted, h)
	}
	var b strings.Builder
	b.WriteString(`# lockhttp policy. Only the console's human loosens it: every loosening
# (a new trusted host, a free or auto rule, shadow mode, ...) is confirmed
# in the console with :review before it applies.

[profiles.default]
# enforce: verdicts apply. shadow: log what would ask or be denied, let it
# pass (the floor and secrets stay enforced).
mode = "enforce"
# exfiltration heuristics: shadow (score logged only), enforce, off
heuristics = "shadow"
buffer_limit = "10MiB"   # largest body held for a human
hold = "60s"             # how long a request waits for the human
connect_grant = "10m"    # an approved CONNECT opens its host for the container this long

# Reads (GET/HEAD/OPTIONS without body) of these hosts are free.
# "*.example.com" covers the subdomains, not example.com itself.
trusted = [
`)
	for _, h := range trusted {
		b.WriteString("  \"" + h + "\",\n")
	}
	b.WriteString(`]

# Hosts never decrypted (certificate pinning): decided at the domain.
splice = []

# Hosts always refused.
deny = []

# Rules, most specific first. verdict: free, auto (auto mode may approve;
# never for messaging, publishing, git push, spliced hosts), ask, deny.
# A rule names a container or none (all containers), never an agent.
#
# [[profiles.default.rules]]
# id      = "npm-audit"
# container = "lea-ab12cd34ef"
# host    = "registry.npmjs.org"
# methods = ["POST"]
# path    = "/-/npm/v1/security/advisories/bulk"
# verdict = "auto"
# max_body = "256KiB"
# expires = "2026-12-31"
`)
	return b.String()
}
