package decide

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// ScoreThreshold is the exfiltration score from which a request asks (in
// enforce mode) or is flagged (shadow).
const ScoreThreshold = 3

var (
	digestRe  = regexp.MustCompile(`^(sha256|sha512|sha1|md5)[:=-]?[0-9a-fA-F]{32,}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	versionRe = regexp.MustCompile(`^v?\d+(\.\d+)*([-+][0-9A-Za-z.-]+)?$`)
)

// exemptParams are query parameters that carry long signatures or tokens
// by design (presigned URLs, OAuth); they are not scored.
var exemptParams = map[string]bool{
	"x-amz-signature": true, "x-amz-credential": true, "x-amz-security-token": true, "x-goog-signature": true,
	"x-goog-credential": true, "sig": true, "signature": true, "se": true, "sp": true, "sv": true, "sr": true, "skoid": true,
	"sktid": true, "skt": true, "ske": true, "sks": true, "skv": true, "code": true, "state": true,
	"code_challenge": true, "nonce": true, "token": true, "jwt": true, "expires": true, "x-amz-date": true,
	"response-content-disposition": true, "rscd": true, "rsct": true, "scope": true, "service": true,
}

// Score computes the exfiltration score of a request and its reasons:
// data in the URL, high-entropy values, deep or random subdomains,
// unusual headers, personal data.
func Score(r Request) (int, []string) {
	score := 0
	var why []string
	hit := func(n int, format string, args ...any) {
		score += n
		why = append(why, fmt.Sprintf(format, args...))
	}
	// Subdomains: evaluated on the name, before any resolution.
	labels := strings.Split(r.Host, ".")
	if len(labels) > 6 {
		hit(2, "%d labels in the host name", len(labels))
	}
	for _, l := range labels {
		if len(l) > 40 {
			hit(2, "a host label of %d characters", len(l))
		} else if len(l) >= 20 && entropy(l) > 3.8 {
			hit(2, "a high-entropy host label")
		}
	}
	if len(r.RawQuery) > 512 {
		hit(2, "query of %d bytes", len(r.RawQuery))
	}
	q, _ := url.ParseQuery(r.RawQuery)
	if len(q) > 20 {
		hit(1, "%d query parameters", len(q))
	}
	for k, vs := range q {
		if exemptParams[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			switch {
			case len(v) > 128:
				hit(2, "query value %s of %d bytes", k, len(v))
			case suspicious(v):
				hit(2, "high-entropy query value %s", k)
			}
		}
	}
	for _, seg := range strings.Split(r.Path, "/") {
		if suspicious(seg) {
			hit(1, "high-entropy path segment")
			break
		}
	}
	if r.Header != nil {
		for name, vs := range r.Header {
			ln := strings.ToLower(name)
			for _, v := range vs {
				switch {
				case strings.HasPrefix(ln, "x-") && (len(v) > 256 || suspicious(v)) && !strings.HasPrefix(ln, "x-amz-") && ln != "x-api-key" && ln != "x-request-id":
					hit(2, "header %s looks like data", name)
				case ln == "user-agent" && len(v) > 256:
					hit(2, "User-Agent of %d bytes", len(v))
				}
			}
		}
	}
	if found := piiIn(r.RawQuery + " " + r.Path); found {
		hit(2, "personal data in the URL")
	}
	return score, why
}

// suspicious reports a value of 32+ characters with entropy above 4
// bits per character, or a long base64/hex blob, that is not a digest or
// a version.
func suspicious(v string) bool {
	if len(v) < 32 || digestRe.MatchString(v) || versionRe.MatchString(v) {
		return false
	}
	return entropy(v) > 4.0 || (len(v) >= 48 && isEncoded(v))
}

var encodedRe = regexp.MustCompile(`^[A-Za-z0-9+/_=-]+$`)

func isEncoded(v string) bool { return encodedRe.MatchString(v) }

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

var piiDetectors = func() []pii.Detector {
	ds, err := pii.Detectors([]string{"email", "iban", "card"})
	if err != nil {
		panic(err)
	}
	return ds
}()

func piiIn(s string) bool {
	u, err := url.QueryUnescape(s)
	if err != nil {
		u = s
	}
	return pii.Detect(u, piiDetectors) != u
}

// secretFormat is a known credential format and the hosts it belongs to.
type secretFormat struct {
	name  string
	re    *regexp.Regexp
	hosts []string
}

var secretFormats = []secretFormat{
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`),
		[]string{"github.com", "api.github.com", "*.github.com", "uploads.github.com", "ghcr.io", "*.githubusercontent.com"}},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), []string{"api.anthropic.com", "console.anthropic.com"}},
	{"AWS access key", regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), []string{"*.amazonaws.com"}},
	{"Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), []string{"slack.com", "*.slack.com"}},
	{"OpenAI key", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_-]{32,}`), []string{"api.openai.com"}},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), []string{"*.googleapis.com"}},
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), nil},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), []string{"registry.npmjs.org"}},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), []string{"gitlab.com", "*.gitlab.com"}},
}

// secretCheck denies a known credential format sent outside its hosts,
// in the URL, the headers or the held body.
func secretCheck(r Request) (Decision, bool) {
	parts := []string{r.Path, r.RawQuery}
	if u, err := url.QueryUnescape(r.RawQuery); err == nil {
		parts = append(parts, u)
	}
	for _, vs := range r.Header {
		parts = append(parts, vs...)
	}
	if r.Body != nil {
		parts = append(parts, string(r.Body))
	}
	text := strings.Join(parts, "\n")
	for _, f := range secretFormats {
		if !f.re.MatchString(text) {
			continue
		}
		legit := false
		for _, h := range f.hosts {
			if policy.HostMatch(h, r.Host) {
				legit = true
			}
		}
		if !legit {
			return deny("secret:"+strings.ReplaceAll(strings.ToLower(f.name), " ", "-"), product.CodeSecretEgress,
				"a "+f.name+" sent to "+r.Host+", outside its own hosts"), true
		}
	}
	return Decision{}, false
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
