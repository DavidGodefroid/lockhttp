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
	if d, stop := decide.Floor(pol, r); stop {
		g.refuse(w, d, id, src, t, true)
		return false
	}
	if d, stop := g.hubTarget(ctx, host); stop {
		g.refuse(w, d, id, src, t, true)
		return false
	}
	fp := RequestFingerprint(src.Container, req.Method, target, req.Header, bodyFP)
	var d decide.Decision
	hard, isHard := decide.Hard(pol, r)
	wd, withdrawn := g.withdrawnRefusal(fp)
	switch {
	case withdrawn:
		d = wd
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
		rec.Base.Approval = "console"
		if out.Auto {
			rec.Base.Approval = "auto"
		}
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
	ws := strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
	if ws {
		out.Header.Set("Connection", "Upgrade")
	} else {
		out.Header.Del("Upgrade")
	}
	out.ContentLength = bodyLen
	if body != nil || rest != nil {
		var rd io.Reader = bytes.NewReader(body)
		if rest != nil {
			rd = io.MultiReader(rd, rest)
			out.ContentLength = req.ContentLength
		}
		out.Body = io.NopCloser(rd)
	} else {
		out.Body = nil
	}
	resp, err := g.transport.RoundTrip(out)
	if err != nil {
		rec.Base.Event, rec.Base.Decision, rec.Base.Error = "error", decisionOf(d), err.Error()
		g.audit(rec)
		msg := "the gate could not reach " + host + "\n"
		fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nX-LockHTTP-Request: %s\r\nContent-Length: %d\r\n\r\n%s", id, len(msg), msg)
		return true
	}
	defer resp.Body.Close()
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
		_ = resp.Write(w)
		done := make(chan struct{})
		go func() { _, _ = io.Copy(rwc, br); close(done) }()
		n, _ = io.Copy(w, rwc)
		_ = rwc.Close()
		<-done
		keep = false
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
