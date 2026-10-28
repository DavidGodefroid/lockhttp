package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// volatileFields are dropped from a JSON body before it is fingerprinted:
// a client that retries regenerates them.
var volatileFields = []string{"timestamp", "nonce", "request_id", "requestId", "ts", "time"}

// BodyFingerprint is the normalised fingerprint of a body: multipart
// parts without their boundary, canonical JSON without volatile fields,
// else the raw bytes.
func BodyFingerprint(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	mt, params, _ := mime.ParseMediaType(contentType)
	switch {
	case strings.HasPrefix(mt, "multipart/") && params["boundary"] != "" && multipartFramed(body, params["boundary"]):
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		h := sha256.New()
		for {
			part, err := mr.NextRawPart()
			if err == io.EOF {
				return "mp:" + hex.EncodeToString(h.Sum(nil))
			}
			if err != nil {
				break
			}
			keys := make([]string, 0, len(part.Header))
			for k := range part.Header {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				fmt.Fprintf(h, "%s:%s\n", k, strings.Join(part.Header[k], ","))
			}
			c, _ := io.ReadAll(part)
			fmt.Fprintf(h, "%d:%s\n", len(c), sum(c))
		}
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		// Canonical only when unambiguous: valid UTF-8, no \u escape (a lone
		// surrogate decodes to U+FFFD, merging spellings), no duplicate key,
		// nothing after the value. Anything else is hashed raw.
		var v any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if utf8.Valid(body) && !bytes.Contains(body, []byte(`\u`)) && noDuplicateKeys(body) && dec.Decode(&v) == nil && atEOF(dec) {
			if m, ok := v.(map[string]any); ok {
				for _, f := range volatileFields {
					// Only a short scalar is volatile: anything that could
					// carry data stays in the fingerprint.
					switch x := m[f].(type) {
					case json.Number, bool, nil:
						delete(m, f)
					case string:
						if len(x) <= 64 {
							delete(m, f)
						}
					}
				}
			}
			if b, err := json.Marshal(v); err == nil {
				return "json:" + sum(b)
			}
		}
	}
	return "raw:" + sum(body)
}

// noDuplicateKeys reports a JSON text whose objects have no duplicate key
// at any depth: a server may keep either value, so a canonical form would
// hide what it acts on.
func noDuplicateKeys(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // next string token is a key
	}
	var stack []*frame
	for {
		t, err := dec.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.key {
			if d, ok := t.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			k, ok := t.(string)
			if !ok || top.keys[k] {
				return false
			}
			top.keys[k], top.key = true, false
			continue
		}
		switch d := t.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, key: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			default:
				stack = stack[:len(stack)-1]
			}
		}
		// A value completed: the enclosing object expects a key next.
		if len(stack) > 0 && stack[len(stack)-1].obj {
			stack[len(stack)-1].key = true
		}
	}
}

// atEOF reports that nothing follows the decoded value.
func atEOF(dec *json.Decoder) bool {
	_, err := dec.Token()
	return err == io.EOF
}

// multipartFramed reports a body with no preamble and no epilogue: the
// multipart reader skips both, so data hidden there would not change the
// normalised fingerprint. Anything else is hashed raw.
func multipartFramed(body []byte, boundary string) bool {
	end := "--" + boundary + "--"
	b := bytes.TrimSuffix(body, []byte("\r\n"))
	return bytes.HasPrefix(body, []byte("--"+boundary+"\r\n")) && bytes.HasSuffix(b, []byte(end)) &&
		bytes.Count(body, []byte(end)) == 1
}

// RequestFingerprint binds an ask (and a single-use authorisation) to a
// request: container, method, URL, significant headers and normalised
// body.
func RequestFingerprint(container, method, url string, h http.Header, bodyFP string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%s\n", container, method, url)
	ct, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	fmt.Fprintf(&b, "ct:%s\n", ct)
	for _, a := range h.Values("Authorization") {
		fmt.Fprintf(&b, "auth:%s\n", sum([]byte(a)))
	}
	var xs []string
	for k, vs := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-") {
			xs = append(xs, strings.ToLower(k)+"="+strings.Join(vs, ","))
		}
	}
	slices.Sort(xs)
	for _, x := range xs {
		fmt.Fprintf(&b, "%s\n", x)
	}
	fmt.Fprintf(&b, "body:%s\n", bodyFP)
	return "sha256:" + sum([]byte(b.String()))
}

var previewDetectors = func() []pii.Detector {
	ds, err := pii.Detectors([]string{"email", "phone", "iban", "card"})
	if err != nil {
		panic(err)
	}
	return ds
}()

var secretLike = regexp.MustCompile(`(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|(AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)

// Preview is the masked start of a body for the approval screen
// (decision D-body): textual bodies only, personal data and secrets
// masked, at most wire.MaxPreview bytes.
func Preview(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	mt, _, _ := mime.ParseMediaType(contentType)
	textual := strings.HasPrefix(mt, "text/") || mt == "application/json" || strings.HasSuffix(mt, "+json") ||
		mt == "application/x-www-form-urlencoded" || mt == "application/xml" || mt == "" && utf8.Valid(body)
	if !textual || !utf8.Valid(body[:min(len(body), wire.MaxPreview)]) {
		return fmt.Sprintf("(%s, %d bytes, not shown)", nonEmpty(mt, "binary"), len(body))
	}
	s := string(body[:min(len(body), wire.MaxPreview)])
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	s = secretLike.ReplaceAllString(s, "<secret>")
	if v, ok := pii.Detect(s, previewDetectors).(string); ok {
		s = v
	}
	s = sanitize.Terminal(s, true)
	if len(body) > wire.MaxPreview {
		s += fmt.Sprintf("\n… (%d bytes in all)", len(body))
	}
	return s
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// PushRefs reads the ref updates of a git-receive-pack request body
// (pkt-lines "old new ref\0caps" up to the flush packet).
func PushRefs(body []byte) []string {
	var out []string
	for len(body) >= 4 && len(out) < wire.MaxRefs {
		n, err := strconv.ParseUint(string(body[:4]), 16, 16)
		if err != nil || n == 0 || int(n) > len(body) || n < 4 {
			break
		}
		line := string(body[4:n])
		body = body[n:]
		if i := strings.IndexByte(line, 0); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		short := func(s string) string { return s[:min(len(s), 12)] }
		switch {
		case strings.Trim(f[0], "0") == "":
			out = append(out, fmt.Sprintf("create %s at %s", f[2], short(f[1])))
		case strings.Trim(f[1], "0") == "":
			out = append(out, fmt.Sprintf("DELETE %s (was %s)", f[2], short(f[0])))
		default:
			out = append(out, fmt.Sprintf("update %s %s..%s", f[2], short(f[0]), short(f[1])))
		}
	}
	return out
}
