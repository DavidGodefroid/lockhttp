package gate

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/audit"

	"github.com/DavidGodefroid/lockhttp/internal/decide"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// serveHTTP decides and forwards one plain or decrypted request. It
// returns whether the connection may carry another request.
func (g *Gate) serveHTTP(ctx context.Context, w io.Writer, br *bufio.Reader, req *http.Request, src wire.Source,
	scheme, host string, port int, tlsMode string) bool {
	start := g.cfg.Now()
	id := newRequestID()
	pol, _ := g.Policy()
	limit := int64(policy.DefaultBufferLimit)
	if pol != nil {
		limit = pol.BufferLimit
	}
	// Hold the body up to the buffer limit (+1 byte to know it is over).
	var body []byte
	var rest io.Reader
	bodyLen := req.ContentLength
	if req.Body != nil && req.ContentLength != 0 {
		buf, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
		if err != nil {
			return false
		}
		body = buf
		if int64(len(buf)) > limit {
			rest = req.Body
			if bodyLen < 0 {
				bodyLen = limit + 1
			}
		} else {
			bodyLen = int64(len(buf))
		}
	}
	if bodyLen < 0 {
		bodyLen = 0
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	target := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + path
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	r := decide.Request{Phase: decide.PhaseHTTP, Container: src.Container, Via: src.Via, Method: req.Method, Host: host, Port: port,
		Path: path, RawQuery: req.URL.RawQuery, Header: req.Header, BodyLen: bodyLen, Body: body, TLS: tlsMode == "mitm"}
	ct := req.Header.Get("Content-Type")
	bodyFP := BodyFingerprint(ct, body)
	t := wire.Target{Phase: "http", TLS: tlsMode, Method: req.Method, Host: host, Port: port, Path: path,
		QueryLen: len(req.URL.RawQuery), ReqBytes: bodyLen, BodyFP: bodyFP, ReqHeaders: headerNames(req.Header)}
	if req.URL.RawQuery != "" {
		t.QueryHash = "sha256:" + sum([]byte(req.URL.RawQuery))
	}
	// A value in a name the agent wrote (the host of the URL or of the Host
	// header, a header name) is refused before anything else: the floor's
	// and the hub's checks would audit the host, and the hub's resolves it
	// (a DNS query would carry the value out).
	if name, why := g.cfg.Secrets.LeakNames([]string{req.URL.Host, req.Host, host}, rawHeaderNames(req.Header)); name != "" || why != "" {
		t.Host, t.Path, t.QueryLen, t.QueryHash, t.BodyFP, t.ReqHeaders = redactedTarget, redactedTarget, 0, "", "", nil
		d := decide.Decision{Verdict: decide.Deny, Rule: "secret:injected", Code: product.CodeSecretEgress,
			Reason: "the request's host or a header name carries the value of the secret " + name + ", which only the gate adds: never send it yourself"}
		if why != "" {
			d.Rule, d.Reason = "secret:unscannable", why+": the gate cannot check it for the value of an injected secret"
		}
		g.refuse(w, d, id, src, t, false)
		return false
	}
	// A secret the gate injects never comes from the agent. The check runs
	// first so that every refusal below, the floor's and the hub's too,
	// audits a target with none of the value: it may be in the path or
	// the query.
	leakName, leak := g.cfg.Secrets.Leak(agentParts(req, path, body)...)
	fs := g.cfg.Secrets.Forms()
	unscannable := ""
	if !leak && !fs.empty() {
		leakName, unscannable = encodedLeak(req.Header.Get("Content-Encoding"), body, rest != nil, fs)
		leak = leakName != ""
	}
	if leak {
		t.Path, t.QueryLen, t.QueryHash, t.BodyFP = redactedTarget, 0, "", ""
	}
	if d, stop := decide.Floor(pol, r); stop {
		g.refuse(w, d, id, src, t, true)
		return false
	}
	if d, stop := g.hubTarget(ctx, host); stop {
		g.refuse(w, d, id, src, t, true)
		return false
	}
	// One in its request is refused, whatever the host (no grant or
	// shadow lifts it).
	if leak {
		d := decide.Decision{Verdict: decide.Deny, Rule: "secret:injected", Code: product.CodeSecretEgress,
			Reason: "the request carries the value of the secret " + leakName + ", which only the gate adds: never send it yourself"}
		g.refuse(w, d, id, src, t, false)
		return rest == nil
	}
	if unscannable != "" {
		d := decide.Decision{Verdict: decide.Deny, Rule: "secret:unscannable", Code: product.CodeSecretEgress,
			Reason: unscannable + ": the gate cannot check it for the value of an injected secret"}
		g.refuse(w, d, id, src, t, false)
		return rest == nil
	}
	ws := strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
	// Every injection to this host and port, whatever its container,
	// methods and paths: a credential one request got may be stored and
	// served back on another path, or to another container, so every
	// request to the host and port gets the response rules below.
	var atHost []policy.Inject
	if pol != nil {
		atHost = pol.InjectAt(host, port)
	}
	if (strings.EqualFold(req.Method, "TRACE") || strings.EqualFold(req.Method, "TRACK")) && len(atHost) > 0 {
		// TRACE echoes the request: never to a host the gate injects into,
		// in any case of the method (a target may not tell "trace" from it).
		d := decide.Decision{Verdict: decide.Deny, Rule: "inject:trace", Code: product.CodeMethod,
			Reason: req.Method + " echoes the request, and the gate adds a credential to " + host + ": refused"}
		g.refuse(w, d, id, src, t, false)
		return rest == nil
	}
	injects, injectWarn := g.injectsFor(pol, src.Container, host, port, tlsMode, req.Method, path)
	if ws && len(atHost) > 0 {
		// The gate does not scan a WebSocket's frames from the target for
		// the credential it adds: no request to an injected host upgrades.
		d := decide.Decision{Verdict: decide.Deny, Rule: "inject:" + atHost[0].ID, Code: product.CodeInject,
			Reason: "the gate adds a credential to " + host + " (inject " + atHost[0].ID + "): a request to it may not upgrade to a WebSocket"}
		g.refuse(w, d, id, src, t, false)
		return rest == nil
	}
	fp := RequestFingerprint(src.Container, req.Method, target, req.Header, bodyFP)
	var d decide.Decision
	hard, isHard := decide.Hard(pol, r)
	switch {
	case isHard:
		d = hard
	case g.grants.UseOnce(fp):
		d = decide.Decision{Verdict: decide.Free, Rule: "grant:once"}
	case req.Method == http.MethodGet && bodyLen == 0 && g.grants.UseRedirect(src.Container, target):
		d = decide.Decision{Verdict: decide.Free, Rule: "grant:redirect"}
	default:
		d = decide.Evaluate(pol, r, g.cfg.Now(), g.cfg.Creds)
	}
	if d.Verdict == decide.Free && rest != nil {
		// Over the buffer limit: only a policy rule may stream it.
		if pol == nil || !isRuleID(pol, d.Rule) {
			d = decide.Decision{Verdict: decide.Deny, Rule: "default:body-limit", Code: product.CodeBodyTooLarge,
				Reason: "the body exceeds the buffer limit (" + policy.FormatSize(limit) + ")"}
		}
	}
	d.Warnings = append(d.Warnings, injectWarn...)
	rec := recordOf(d, id, src, t)
	switch d.Verdict {
	case decide.Deny:
		g.refuse(w, d, id, src, t, false)
		return rest == nil
	case decide.Ask:
		if rest != nil {
			d = decide.Decision{Verdict: decide.Deny, Rule: d.Rule, Code: product.CodeBodyTooLarge,
				Reason: "the body exceeds the buffer limit (" + policy.FormatSize(limit) + "): it cannot be held for a human"}
			g.refuse(w, d, id, src, t, false)
			return false
		}
		params := wire.ApproveParams{RequestID: id, Source: src, Target: t, ContentType: ct, Preview: Preview(ct, body),
			Rule: d.Rule, RuleAuto: !d.NeverAuto, NeverAuto: d.NeverAuto, Red: d.Red, Class: d.Class, Warnings: d.Warnings, Score: d.Score}
		if d.Class == "receive-pack" {
			params.Refs = PushRefs(body)
			params.Preview = ""
		}
		key := src.Container + "|" + host + "|" + req.Method + "|" + path
		out := g.ask(params, fp, key, holdOf(pol), func(clientGone bool) {
			if clientGone {
				g.grants.GrantOnce(fp)
			}
		})
		if !out.Approved {
			rec.Base = audit.Base{Event: "refused", Decision: "refused", Code: out.Code, Reason: out.Reason, Warnings: d.Warnings, Ticket: out.Ticket}
			g.audit(rec)
			writeRefusalTicket(w, id, out.Code, out.Reason, out.Ticket, false)
			return true
		}
		rec.Base.Approval = ApprovalHubRun
	}
	// Forward.
	out := req.Clone(ctx)
	out.RequestURI = ""
	out.URL, _ = url.Parse(target)
	// The Host sent upstream is the host decided, never the client's.
	out.Host = host
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		out.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	// Credential injection, after the verdict: the agent never held it.
	injected := map[string][]string{}
	for _, inj := range injects {
		v, err := g.cfg.Secrets.Value(inj.Credential)
		if err != nil {
			d := decide.Decision{Verdict: decide.Deny, Rule: "inject:" + inj.ID, Code: product.CodeInject,
				Reason: "inject " + inj.ID + ": " + err.Error()}
			g.refuse(w, d, id, src, t, false)
			return rest == nil
		}
		if inj.Scheme != "" {
			v = inj.Scheme + " " + v
		}
		if len(out.Header.Values(inj.Header)) > 0 {
			rec.Warnings = append(rec.Warnings, "replaced the agent's "+inj.Header+" header")
		}
		out.Header.Del(inj.Header)
		out.Header.Set(inj.Header, v)
		rec.Injected = append(rec.Injected, inj.ID+":"+inj.Header)
		raw, _ := g.cfg.Secrets.Value(inj.Credential)
		injected[inj.Credential] = append(injected[inj.Credential], raw)
	}
	var respForms *formSet
	if len(atHost) > 0 {
		// Every response from a host the gate injects into is scanned for
		// the values (every one loaded: a rotated-out one may be stored
		// there too), whether this request got the header or not: it
		// comes unencoded, whole (no range: two ranges would join the
		// halves of a redacted value), and no proxy on the way echoes
		// the request (Max-Forwards).
		respForms = g.cfg.Secrets.Forms()
		if respForms.empty() && len(injected) > 0 {
			respForms = formsOf(injected)
		}
		out.Header.Set("Accept-Encoding", "identity")
		for _, h := range []string{"Max-Forwards", "Range", "If-Range"} {
			out.Header.Del(h)
		}
	}
	if ws && !fs.empty() {
		// The client's frames are scanned: no compression of them.
		out.Header.Del("Sec-Websocket-Extensions")
	}
	if ws {
		out.Header.Set("Connection", "Upgrade")
	} else {
		out.Header.Del("Upgrade")
	}
	out.ContentLength = bodyLen
	var streamScan *scanReader
	if body != nil || rest != nil {
		var rd io.Reader = bytes.NewReader(body)
		if rest != nil {
			rd = io.MultiReader(rd, rest)
			out.ContentLength = req.ContentLength
			if !fs.empty() {
				// Past the held prefix, the body is scanned as it streams:
				// a value of a secret aborts the request before it goes
				// out whole.
				streamScan = &scanReader{r: rd, fs: fs}
				rd = streamScan
			}
		}
		out.Body = io.NopCloser(rd)
	} else {
		out.Body = nil
	}
	resp, err := g.transport.RoundTrip(out)
	if streamScan != nil && len(streamScan.found) > 0 {
		if err == nil {
			resp.Body.Close()
		}
		t.Path, t.QueryLen, t.QueryHash, t.BodyFP = redactedTarget, 0, "", ""
		d := decide.Decision{Verdict: decide.Deny, Rule: "secret:injected", Code: product.CodeSecretEgress,
			Reason: "the streamed body carries the value of the secret " + streamScan.found[0] + ", which only the gate adds: never send it yourself"}
		g.refuse(w, d, id, src, t, false)
		return false
	}
	if err != nil {
		rec.Base.Event, rec.Base.Decision, rec.Base.Error = "error", decisionOf(d), err.Error()
		g.audit(rec)
		msg := "the gate could not reach " + host + "\n"
		fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nX-LockHTTP-Request: %s\r\nContent-Length: %d\r\n\r\n%s", id, len(msg), msg)
		return true
	}
	defer resp.Body.Close()
	if len(atHost) > 0 {
		why := ""
		if ct := strings.ToLower(resp.Header.Get("Content-Type")); resp.StatusCode == http.StatusPartialContent ||
			resp.Header.Get("Content-Range") != "" || strings.HasPrefix(ct, "multipart/byteranges") {
			// The gate asked for the whole response: a part of it cannot be
			// checked (the rest of a value may be in another part).
			why = "the response is partial (" + resp.Status + ")"
		} else if resp.StatusCode == http.StatusSwitchingProtocols {
			why = "the response switches protocols"
		} else if !respForms.empty() {
			why = redactResponse(resp, respForms, &rec)
		}
		if why != "" {
			d := decide.Decision{Verdict: decide.Deny, Rule: "inject:" + atHost[0].ID, Code: product.CodeInject,
				Reason: why + ": the gate cannot check it for the credential it adds to " + host}
			g.refuse(w, d, id, src, t, false)
			return false
		}
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" && pol != nil {
		if u, err := out.URL.Parse(loc); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
			th, tp := splitHostPort(u.Host, map[string]int{"https": 443, "http": 80}[u.Scheme])
			if pol.CDNFor(host, th) {
				u.Host = net.JoinHostPort(th, strconv.Itoa(tp))
				g.grants.GrantRedirect(src.Container, u.String())
			}
		}
	}
	resp.Header.Set("X-LockHTTP-Request", id)
	keep := !req.Close && !resp.Close
	var n int64
	if resp.StatusCode == http.StatusSwitchingProtocols {
		rwc, ok := resp.Body.(io.ReadWriteCloser)
		if !ok {
			return false
		}
		if !fs.empty() && resp.Header.Get("Sec-Websocket-Extensions") != "" {
			// An extension it was not offered (compression) would hide
			// the client's frames from the scan.
			_ = rwc.Close()
			rec.Base.Event, rec.Base.Decision, rec.Base.Error = "error", decisionOf(d), "the target chose a WebSocket extension the gate removed"
			g.audit(rec)
			return false
		}
		// The head only: Response.Write would read a byte of the body
		// (the upgraded connection) first, waiting on a target that
		// waits for the client to speak.
		head := *resp
		head.Body = nil
		_ = head.Write(w)
		done := make(chan struct{})
		var wsLeak string
		go func() {
			if fs.empty() {
				_, _ = io.Copy(rwc, br)
			} else {
				var oversized bool
				_, wsLeak, oversized = copyWebSocket(rwc, br, fs, limit)
				if oversized {
					rec.Warnings = append(rec.Warnings, "closed: a WebSocket frame exceeds the buffer limit, the gate cannot check it")
				}
				_ = rwc.Close()
			}
			close(done)
		}()
		n, _ = io.Copy(w, rwc)
		_ = rwc.Close()
		<-done
		keep = false
		if wsLeak != "" {
			rec.Base = audit.Base{Event: "refused", Decision: "refused", Code: string(product.CodeSecretEgress), Warnings: rec.Base.Warnings,
				Reason: "a WebSocket frame carries the value of the secret " + wsLeak + ", which only the gate adds: the connection is closed"}
			rec.Rule = "secret:injected"
			rec.Status, rec.RespBytes, rec.DurationMS = resp.StatusCode, n, g.cfg.Now().Sub(start).Milliseconds()
			g.audit(rec)
			return false
		}
	} else {
		cw := &countWriter{w: w}
		if err := resp.Write(cw); err != nil {
			keep = false
		}
		n = cw.n
	}
	rec.Base.Event, rec.Base.Decision = "free", decisionOf(d)
	if rec.Base.Approval != "" {
		rec.Base.Event, rec.Base.Decision = "approved", "approved"
	}
	rec.Status, rec.RespBytes, rec.DurationMS = resp.StatusCode, n, g.cfg.Now().Sub(start).Milliseconds()
	g.audit(rec)
	return keep
}

// injectsFor returns the injections of a request, and the warnings that
// say so on the approval screen and in the audit. A header is injected
// into a decrypted HTTPS request, or a plain HTTP one to an internal
// host: never in clear text across the internet.
func (g *Gate) injectsFor(pol *policy.Policy, container, host string, port int, tlsMode, method, path string) ([]policy.Inject, []string) {
	if pol == nil {
		return nil, nil
	}
	var out []policy.Inject
	var warns []string
	for _, inj := range pol.InjectFor(container, host, port) {
		switch {
		case inj.MatchesRequest(method, path):
		case len(inj.Paths) > 0 && policy.AmbiguousPath(path):
			warns = append(warns, "inject "+inj.ID+" skipped: the path is not canonical (a dot segment, a byte or escape outside the allowlist, invalid or overlong UTF-8), which a target may resolve outside "+strings.Join(inj.Paths, ","))
		default:
			warns = append(warns, "inject "+inj.ID+" skipped: the policy does not name "+method+" "+path)
		}
	}
	for _, inj := range pol.InjectForRequest(container, host, port, method, path) {
		if tlsMode != "mitm" && !(tlsMode == "plain" && internalHost(pol, host)) {
			warns = append(warns, "inject "+inj.ID+" skipped: plain HTTP to a host that is not internal")
			continue
		}
		out = append(out, inj)
		warns = append(warns, "the gate adds "+inj.Header+" (secret "+inj.Credential+", inject "+inj.ID+"): the agent does not hold it")
	}
	return out, warns
}

// agentParts are the parts of a request the agent wrote, for the leak
// check of the injected secrets.
func agentParts(req *http.Request, path string, body []byte) [][]byte {
	parts := [][]byte{[]byte(path), []byte(req.URL.Path), []byte(req.URL.RawQuery), body}
	if q, err := url.QueryUnescape(req.URL.RawQuery); err == nil {
		parts = append(parts, []byte(q))
	}
	if req.URL.User != nil {
		parts = append(parts, []byte(req.URL.User.String()))
	}
	for _, vs := range req.Header {
		for _, v := range vs {
			parts = append(parts, []byte(v))
		}
	}
	return parts
}

func isRuleID(p *policy.Policy, id string) bool {
	for _, r := range p.Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// redactedTarget replaces, in the audit, a part of the target that
// carries an injected secret.
const redactedTarget = "(redacted: carries an injected secret)"

// headerValues lists the request's header values, for the leak check.
func headerValues(h http.Header) [][]byte {
	var out [][]byte
	for _, vs := range h {
		for _, v := range vs {
			out = append(out, []byte(v))
		}
	}
	return out
}

// rawHeaderNames lists the request's header names as received, for the
// leak check.
func rawHeaderNames(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// headerNames lists the request's header names (lower case), for the
// audit: never their values.
func headerNames(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, strings.ToLower(k))
	}
	return sortedStrings(out)
}

func sortedStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
