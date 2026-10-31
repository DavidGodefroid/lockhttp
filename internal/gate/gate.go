// Package gate is lockhttp's data plane: the HTTP(S) proxy every request
// of the agents goes through. It decides each request with the policy the
// console approved (it never reads a policy file), holds what needs a
// human, asks lockhub, and audits what it lets through or refuses.
package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"

	"github.com/DavidGodefroid/lockhttp/internal/decide"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// CertSource issues the leaf certificate presented to a client for host
// (MITM). The CA key stays with the signer.
type CertSource interface {
	Certificate(ctx context.Context, host string) (*tls.Certificate, error)
}

// Config configures a gate.
type Config struct {
	Profile string
	// Upstream is the proxy the gate sends through (squid on loopback);
	// nil dials the target itself, refusing private addresses.
	Upstream *url.URL
	Sources  *Sources
	Creds    *Credentials
	Console  Console
	Audit    *AuditLog
	// StatusFile is rewritten when the console state or the pending
	// counts change ("" for none).
	StatusFile string
	// Certs enables MITM; nil decides CONNECTs at the domain.
	Certs CertSource
	// UpstreamTLS verifies the targets (nil: the system roots). The gate
	// never skips verification.
	UpstreamTLS *tls.Config
	// Dial replaces the network dialer (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Resolve replaces the resolver of direct mode (tests).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Hub sends the asks to lockhub (required: the gate is hub-attached
	// only); the console serves the policy.
	Hub *Hub
	// PolicyPoll is how often the policy is fetched (2 s by default).
	PolicyPoll time.Duration
	Now        func() time.Time
	// Log receives operational lines (not the audit).
	Log io.Writer
}

type polState struct {
	p  *policy.Policy
	fp string
}

// Gate is a running data plane.
type Gate struct {
	cfg       Config
	queue     *Queue
	grants    *Grants
	pol       atomic.Pointer[polState]
	consoleUp atomic.Bool
	transport *http.Transport

	statusMu sync.Mutex
	status   Status
}

// New returns a gate.
func New(cfg Config) *Gate {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PolicyPoll == 0 {
		cfg.PolicyPoll = 2 * time.Second
	}
	if cfg.Sources == nil {
		cfg.Sources = NewSources("")
	}
	if cfg.Creds == nil {
		cfg.Creds = NewCredentials("")
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	if cfg.Hub == nil {
		panic("gate: Config.Hub is required (the gate is hub-attached only)")
	}
	g := &Gate{cfg: cfg, grants: NewGrants(cfg.Now)}
	// A hub decision may take hours: its asks wait side by side.
	g.queue = NewQueue(g.hubApprove)
	// A renewal (the hub's renew request, or Renew on a request sent
	// again) checks the plan as the run's recheck does; reveals and
	// renewals are audited.
	cfg.Hub.Client.SetRecompute(g.recompute)
	cfg.Hub.Client.OnRequest(g.hubRequest)
	g.pol.Store(&polState{})
	g.status = Status{Version: ContractVersion, Console: "down", PendingByContainer: map[string]int{}}
	g.queue.onChange = func(total int, by map[string]int) {
		g.updateStatus(func(s *Status) { s.Pending, s.PendingByContainer = total, by })
	}
	g.transport = &http.Transport{
		DialContext:         g.dialTarget,
		TLSClientConfig:     cfg.UpstreamTLS,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	if cfg.Upstream != nil {
		g.transport.Proxy = http.ProxyURL(cfg.Upstream)
		g.transport.DialContext = g.dialer
	}
	return g
}

func (g *Gate) dialer(ctx context.Context, network, addr string) (net.Conn, error) {
	if g.cfg.Dial != nil {
		return g.cfg.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Policy returns the policy in force (nil: none received yet) and its
// fingerprint.
func (g *Gate) Policy() (*policy.Policy, string) {
	s := g.pol.Load()
	return s.p, s.fp
}

// Stopped is closed once Run's queue stopped and every ask it was
// answering ended (in hub mode, their tickets withdrawn).
func (g *Gate) Stopped() <-chan struct{} { return g.queue.stopped }

// SetPolicy installs a policy (tests and the poller).
func (g *Gate) SetPolicy(p *policy.Policy, fp string) { g.pol.Store(&polState{p: p, fp: fp}) }

func (g *Gate) updateStatus(f func(*Status)) {
	g.statusMu.Lock()
	defer g.statusMu.Unlock()
	f(&g.status)
	g.status.Updated = g.cfg.Now().UTC().Format(time.RFC3339)
	_ = writeStatus(g.cfg.StatusFile, g.status)
}

// Run polls the policy, runs the ask queue and reloads the source files
// until ctx ends.
func (g *Gate) Run(ctx context.Context) {
	go g.queue.Run(ctx)
	h := g.cfg.Hub
	go h.Client.Watch(ctx, h.Plans, func(err error) { fmt.Fprintln(g.cfg.Log, "lockhttp gate: hub:", err) })
	t := time.NewTicker(g.cfg.PolicyPoll)
	defer t.Stop()
	for {
		g.poll(ctx)
		g.cfg.Sources.Reload()
		g.cfg.Creds.Reload()
		g.grants.Sweep()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (g *Gate) poll(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, err := g.cfg.Console.Policy(cctx)
	if err != nil {
		if g.consoleUp.Swap(false) {
			fmt.Fprintln(g.cfg.Log, "lockhttp gate: console lost:", err)
		}
		g.updateStatus(func(s *Status) { s.Console = "down" })
		return
	}
	p := policy.Canonical(res.Policy)
	if p.Fingerprint() != res.Fingerprint {
		fmt.Fprintln(g.cfg.Log, "lockhttp gate: the console's policy does not match its fingerprint: kept the previous one")
		return
	}
	if _, fp := g.Policy(); fp != res.Fingerprint {
		fmt.Fprintln(g.cfg.Log, "lockhttp gate: policy", res.Fingerprint)
	}
	g.SetPolicy(&p, res.Fingerprint)
	if !g.consoleUp.Swap(true) {
		fmt.Fprintln(g.cfg.Log, "lockhttp gate: console up")
	}
	g.updateStatus(func(s *Status) { s.Console, s.PolicyFP = "up", res.Fingerprint })
}

// Serve accepts connections on ln until it is closed.
func (g *Gate) Serve(ctx context.Context, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go g.handle(ctx, c)
	}
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "h-" + strconv.FormatInt(time.Now().UnixMilli(), 36) + "-" + hex.EncodeToString(b[:])
}

func localAddr(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.LocalAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// proxyAuth reads Basic Proxy-Authorization: the agent name and token.
func proxyAuth(h http.Header) (user, token string) {
	v := h.Get("Proxy-Authorization")
	b64, ok := strings.CutPrefix(v, "Basic ")
	if !ok {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", ""
	}
	user, token, _ = strings.Cut(string(raw), ":")
	return user, token
}

// hopHeaders are removed before a request goes upstream.
var hopHeaders = []string{"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "X-Lea-Source",
	"Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding"}

func (g *Gate) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	// Large enough for a whole TLS record (a ClientHello is peeked).
	br := bufio.NewReaderSize(c, 20<<10)
	local := localAddr(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		user, token := proxyAuth(req.Header)
		leaSource := req.Header.Get("X-Lea-Source")
		src, err := g.cfg.Sources.Resolve(local, user, token, leaSource)
		if leaSource != "" && src.Via != "keyproxy" {
			fmt.Fprintf(g.cfg.Log, "lockhttp gate: ignored X-Lea-Source from %s\n", local)
		}
		if err != nil {
			id := newRequestID()
			g.audit(wire.Record{Base: audit.Base{Event: "refused", Decision: "refused", Code: string(product.CodeSourceUnknown), Error: err.Error()},
				RequestID: id, Target: wire.Target{Method: req.Method, Host: hostOnly(req.Host)}, Rule: "source"})
			writeRefusal(c, id, string(product.CodeSourceUnknown), "the gate cannot tell which container sent this request", req.Method == http.MethodConnect)
			return
		}
		for _, h := range []string{"Proxy-Authorization", "X-Lea-Source", "Proxy-Connection"} {
			req.Header.Del(h)
		}
		if req.Method == http.MethodConnect {
			g.connect(ctx, c, br, req, src)
			return
		}
		if req.URL == nil || req.URL.Host == "" || (req.URL.Scheme != "http") {
			writeRefusal(c, newRequestID(), string(product.CodeFloor), "send absolute http:// URLs, or CONNECT for https", false)
			return
		}
		host, port := splitHostPort(req.URL.Host, 80)
		if req.Host != "" {
			if hh, hp := splitHostPort(req.Host, 80); hh != host || hp != port {
				writeRefusal(c, newRequestID(), string(product.CodeFloor), "the Host header differs from the request URL", true)
				return
			}
		}
		if !g.serveHTTP(ctx, c, br, req, src, "http", host, port, "plain") {
			return
		}
	}
}

func hostOnly(hp string) string {
	h, _ := splitHostPort(hp, 0)
	return h
}

func splitHostPort(hp string, def int) (string, int) {
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return strings.ToLower(strings.Trim(hp, "[]")), def
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		return strings.ToLower(host), -1
	}
	return strings.ToLower(strings.TrimSuffix(host, ".")), p
}

func (g *Gate) audit(rec wire.Record) {
	if rec.PolicyFP == "" {
		_, rec.PolicyFP = g.Policy()
	}
	rec.Profile = g.cfg.Profile
	g.cfg.Audit.Append(rec)
}

// writeRefusal answers 403 with the refusal code, on a CONNECT (no body
// framing kept: the connection closes) or a request.
func writeRefusal(w io.Writer, id, c, reason string, connect bool) {
	writeRefusalTicket(w, id, c, reason, "", connect)
}

// writeRefusalTicket is writeRefusal naming the hub ticket the request
// waits on (X-LockHTTP-Ticket), when tk is not "".
func writeRefusalTicket(w io.Writer, id, c, reason, tk string, connect bool) {
	body := fmt.Sprintf("LockHTTP refused this request (%s): %s\n", c, reason)
	hint := hintFor(c)
	if tk != "" && c == string(product.CodeTimeout) {
		// Hub mode: the same request sent again renews the expired ticket.
		hint = "Ask the user to watch the hub, then send the same request again: it asks the hub again (a renewal of the expired ticket)."
	}
	if hint != "" {
		body += hint + "\n"
	}
	body += "request id: " + id + "\n"
	extra := ""
	if tk != "" {
		body += "hub ticket: " + tk + "\n"
		extra = "X-LockHTTP-Ticket: " + tk + "\r\n"
	}
	status := "403 Forbidden"
	fmt.Fprintf(w, "HTTP/1.1 %s\r\nContent-Type: text/plain; charset=utf-8\r\nX-LockHTTP-Code: %s\r\nX-LockHTTP-Request: %s\r\n%sContent-Length: %d\r\n", status, c, id, extra, len(body))
	if connect {
		fmt.Fprint(w, "Connection: close\r\n")
	}
	fmt.Fprint(w, "\r\n"+body)
}

func hintFor(code string) string {
	switch code {
	case "E_NO_CONSOLE":
		return "No lockhttp console is running: ask the user to start it (lox up)."
	case "E_PENDING":
		return "The request waits for the human on lockhub: retry the same request in a moment."
	case "E_DENIED", "E_TIMEOUT":
		return "Do not retry the same request; ask the user."
	case "E_HOST_UNKNOWN", "E_CLAUDE_API_PARAM", "E_EXFIL_SUSPECT", "E_RULE", "E_METHOD":
		return "Only the human can allow this: ask the user (a durable opening is a policy rule they confirm in the console)."
	}
	return ""
}

// ask holds a request for the human. It returns the outcome, or an
// E_PENDING/E_NO_CONSOLE outcome when it cannot wait.
func (g *Gate) ask(p wire.ApproveParams, fp, key string, hold time.Duration, onApprove func(clientGone bool)) Outcome {
	if !g.consoleUp.Load() {
		return Outcome{Code: string(product.CodeNoConsole), Reason: "no lockhttp console is running"}
	}
	ch, cancel := g.queue.Submit(fp, key, p, onApprove)
	t := time.NewTimer(hold)
	defer t.Stop()
	select {
	case out := <-ch:
		return out
	case <-t.C:
		cancel()
		if h := g.cfg.Hub; h != nil {
			// The ticket may still be on its way (hubSubmit): wait for it a
			// moment, so that the answer names it.
			tk := h.ticketOf(fp)
			for i := 0; tk == "" && i < 50 && g.queue.queued(fp); i++ {
				time.Sleep(20 * time.Millisecond)
				tk = h.ticketOf(fp)
			}
			if tk != "" {
				return Outcome{Code: string(product.CodePending), Ticket: tk, Reason: "the request waits for a decision on the hub (ticket " + tk + ")"}
			}
		}
		return Outcome{Code: string(product.CodePending), Reason: "the request waits for the human (kept on the hub)"}
	}
}

func holdOf(p *policy.Policy) time.Duration {
	if p == nil {
		return policy.DefaultHold * time.Second
	}
	return time.Duration(p.Hold) * time.Second
}

func grantOf(p *policy.Policy) time.Duration {
	if p == nil {
		return policy.DefaultConnectGrant * time.Second
	}
	return time.Duration(p.ConnectGrant) * time.Second
}

func recordOf(d decide.Decision, id string, src wire.Source, t wire.Target) wire.Record {
	rec := wire.Record{RequestID: id, Source: src, Target: t, Rule: d.Rule, Class: d.Class}
	rec.Warnings = d.Warnings
	if d.Shadow != "" {
		rec.Shadow = string(d.Shadow)
	}
	if d.Score >= decide.ScoreThreshold && d.Verdict == decide.Free {
		rec.ShadowScore = d.Score
	} else {
		rec.Score = d.Score
	}
	return rec
}

// connect handles a CONNECT: at the domain, or into MITM.
func (g *Gate) connect(ctx context.Context, c net.Conn, br *bufio.Reader, req *http.Request, src wire.Source) {
	start := g.cfg.Now()
	id := newRequestID()
	host, port := splitHostPort(req.Host, 443)
	pol, _ := g.Policy()
	r := decide.Request{Phase: decide.PhaseConnect, Container: src.Container, Via: src.Via, Method: http.MethodConnect, Host: host, Port: port}
	t := wire.Target{Phase: "connect", TLS: "connect", Method: http.MethodConnect, Host: host, Port: port}
	if d, stop := decide.Floor(pol, r); stop {
		g.refuse(c, d, id, src, t, true)
		return
	}
	if d, stop := g.hubTarget(ctx, host); stop {
		g.refuse(c, d, id, src, t, true)
		return
	}
	_, internal := policy.InternalHost{}, false
	if pol != nil {
		_, internal = pol.InternalHost(host)
	}
	mitm := g.cfg.Certs != nil && port == 443 && !internal && (pol == nil || !pol.Spliced(host))
	if mitm {
		if pol != nil && pol.Denied(host) {
			g.refuse(c, decide.Decision{Verdict: decide.Deny, Rule: "deny-list", Code: product.CodeRule, Reason: host + " is on the policy's deny list"}, id, src, t, true)
			return
		}
		g.mitm(ctx, c, br, host, port, src)
		return
	}
	hostport := net.JoinHostPort(host, strconv.Itoa(port))
	var d decide.Decision
	if g.grants.Connect(src.Container, hostport) {
		d = decide.Decision{Verdict: decide.Free, Rule: "grant:connect", Class: "connect"}
	} else {
		d = decide.Evaluate(pol, r, g.cfg.Now(), g.cfg.Creds)
	}
	rec := recordOf(d, id, src, t)
	switch d.Verdict {
	case decide.Deny:
		g.refuse(c, d, id, src, t, true)
		return
	case decide.Ask:
		grant := grantOf(pol)
		params := wire.ApproveParams{RequestID: id, Source: src, Target: t, Rule: d.Rule, RuleAuto: false, NeverAuto: true,
			Red: d.Red, Class: d.Class, Warnings: d.Warnings, Grant: int64(grant / time.Second)}
		key := src.Container + "|" + hostport
		out := g.ask(params, "connect|"+key, key, holdOf(pol), func(bool) { g.grants.GrantConnect(src.Container, hostport, grant) })
		if !out.Approved {
			rec.Base = audit.Base{Event: "refused", Decision: "refused", Code: out.Code, Reason: out.Reason, Warnings: d.Warnings, Ticket: out.Ticket}
			g.audit(rec)
			writeRefusalTicket(c, id, out.Code, out.Reason, out.Ticket, true)
			return
		}
		g.grants.GrantConnect(src.Container, hostport, grant)
		rec.Base.Approval = "hub"
	}
	// FREE (or approved): open the tunnel.
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	hello, sni, isTLS, complete := peekClientHello(c, br)
	if why := helloRefusal(host, port, internalHost(pol, host), sni, isTLS, complete); why != "" {
		rec.Base = audit.Base{Event: "refused", Decision: "refused", Code: string(product.CodeFloor), Reason: why}
		rec.Rule = "floor:sni"
		g.audit(rec)
		return
	}
	up, err := g.tunnel(ctx, host, port)
	if err != nil {
		rec.Base = audit.Base{Event: "error", Decision: decisionOf(d), Error: err.Error()}
		g.audit(rec)
		return
	}
	defer up.Close()
	if _, err := up.Write(hello); err != nil {
		return
	}
	in, out := splice(c, br, up)
	rec.Base.Event, rec.Base.Decision = "free", decisionOf(d)
	if rec.Base.Approval != "" {
		rec.Base.Event, rec.Base.Decision = "approved", "approved"
	}
	rec.ReqBytes, rec.RespBytes = in+int64(len(hello)), out
	rec.DurationMS = g.cfg.Now().Sub(start).Milliseconds()
	g.audit(rec)
}

func decisionOf(d decide.Decision) string {
	if d.Shadow != "" {
		return "shadow-" + string(d.Shadow)
	}
	return string(d.Verdict)
}

func (g *Gate) refuse(w io.Writer, d decide.Decision, id string, src wire.Source, t wire.Target, connect bool) {
	rec := recordOf(d, id, src, t)
	rec.Base = audit.Base{Event: "refused", Decision: "refused", Code: string(d.Code), Reason: d.Reason, Warnings: d.Warnings}
	g.audit(rec)
	writeRefusal(w, id, string(d.Code), d.Reason, connect)
}

func internalHost(p *policy.Policy, host string) bool {
	if p == nil {
		return false
	}
	_, ok := p.InternalHost(host)
	return ok
}

// helloRefusal checks what a client sends first in a tunnel. On port 443
// it must be a complete TLS ClientHello naming the CONNECT host; on other
// ports (internal hosts, plain port 80) a ClientHello, if any, must name
// it too. "" lets it through.
func helloRefusal(host string, port int, internal bool, sni string, isTLS, complete bool) string {
	switch {
	case isTLS && !complete:
		return "the TLS ClientHello could not be read whole"
	case isTLS && sni != "" && !strings.EqualFold(strings.TrimSuffix(sni, "."), host):
		return "TLS server name " + sni + " differs from the CONNECT host"
	case port == 443 && !internal && !isTLS:
		return "not TLS on port 443"
	case port == 443 && !internal && sni == "":
		return "a TLS ClientHello without a server name on port 443"
	}
	return ""
}

// peekClientHello reads the first TLS record from the client (10 s) and
// returns it with its server name; complete is false when the record
// could not be read whole or parsed. A non-TLS first byte returns what
// was buffered and isTLS false.
func peekClientHello(c net.Conn, br *bufio.Reader) (raw []byte, sni string, isTLS, complete bool) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	head, err := br.Peek(5)
	if err != nil || head[0] != 0x16 {
		n := br.Buffered()
		b, _ := br.Peek(n)
		raw = append([]byte(nil), b...)
		_, _ = br.Discard(n)
		return raw, "", false, false
	}
	n := int(head[3])<<8 | int(head[4])
	rec, err := br.Peek(5 + n)
	if err != nil {
		return nil, "", true, false
	}
	raw = append([]byte(nil), rec...)
	_, _ = br.Discard(len(rec))
	sni, ok := serverName(raw)
	return raw, sni, true, ok
}

// serverName parses the SNI of a ClientHello record; ok is false when the
// record is not a well-formed ClientHello ("" and true: no SNI).
func serverName(rec []byte) (string, bool) {
	if len(rec) < 5+4+2+32+1 {
		return "", false
	}
	p := rec[5:]
	if p[0] != 1 { // handshake type ClientHello
		return "", false
	}
	p = p[4:]       // type + length
	p = p[2+32:]    // version + random
	if len(p) < 1 { //
		return "", false
	}
	sl := int(p[0])
	if len(p) < 1+sl+2 {
		return "", false
	}
	p = p[1+sl:]
	cl := int(p[0])<<8 | int(p[1])
	if len(p) < 2+cl+1 {
		return "", false
	}
	p = p[2+cl:]
	ml := int(p[0])
	if len(p) < 1+ml+2 {
		return "", false
	}
	p = p[1+ml:]
	el := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < el {
		return "", false
	}
	p = p[:el]
	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < l {
			return "", false
		}
		if typ == 0 { // server_name
			d := p[:l]
			if len(d) < 5 {
				return "", false
			}
			d = d[2:]
			if d[0] != 0 {
				return "", false
			}
			nl := int(d[1])<<8 | int(d[2])
			if len(d) < 3+nl {
				return "", false
			}
			return strings.ToLower(string(d[3 : 3+nl])), true
		}
		p = p[l:]
	}
	return "", len(p) == 0
}

// tunnel opens a raw connection to host:port: through the upstream proxy
// (CONNECT), or directly once the name resolves to a public address.
func (g *Gate) tunnel(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if g.cfg.Upstream == nil {
		return g.dialTarget(dctx, "tcp", addr)
	}
	up, err := g.dialer(dctx, "tcp", g.cfg.Upstream.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
	ubr := bufio.NewReader(up)
	resp, err := http.ReadResponse(ubr, &http.Request{Method: http.MethodConnect})
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		up.Close()
		return nil, fmt.Errorf("upstream proxy refused %s: %s", addr, resp.Status)
	}
	_ = up.SetReadDeadline(time.Time{})
	if ubr.Buffered() > 0 {
		return &bufConn{Conn: up, r: ubr}, nil
	}
	return up, nil
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// dialTarget dials a target directly (no upstream proxy): it resolves
// the name only now, after the decision, and refuses private, loopback,
// link-local and other non-public addresses unless the host is an
// internal host.
func (g *Gate) dialTarget(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	resolve := g.cfg.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if g.onHubNet(ips) {
		return nil, fmt.Errorf("%s resolves into the hub's network: refused", host)
	}
	pol, _ := g.Policy()
	internal := false
	if pol != nil {
		_, internal = pol.InternalHost(host)
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !internal && !publicAddr(ip) {
			return nil, fmt.Errorf("%s resolves to a non-public address (%s): refused", host, ip)
		}
	}
	var last error
	for _, ip := range ips {
		c, err := g.dialer(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("%s: no address", host)
	}
	return nil, last
}

func publicAddr(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("fc00::/7"),
}

// splice copies both ways until either side closes; it returns the
// bytes sent and received.
func splice(client net.Conn, br *bufio.Reader, up net.Conn) (in, out int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, _ = io.Copy(client, up)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = client.Close()
		}
	}()
	in, _ = io.Copy(up, br)
	if cw, ok := up.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = up.Close()
	}
	wg.Wait()
	return in, out
}

// mitm terminates the client's TLS with a leaf for host and decides each
// request inside.
func (g *Gate) mitm(ctx context.Context, c net.Conn, br *bufio.Reader, host string, port int, src wire.Source) {
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	hello, sni, isTLS, complete := peekClientHello(c, br)
	id := newRequestID()
	t := wire.Target{Phase: "connect", TLS: "mitm", Method: http.MethodConnect, Host: host, Port: port}
	if why := helloRefusal(host, port, false, sni, isTLS, complete); why != "" {
		g.audit(wire.Record{Base: audit.Base{Event: "refused", Decision: "refused", Code: string(product.CodeFloor), Reason: why}, RequestID: id, Source: src, Target: t, Rule: "floor:sni"})
		return
	}
	cert, err := g.cfg.Certs.Certificate(ctx, host)
	if err != nil {
		g.audit(wire.Record{Base: audit.Base{Event: "error", Decision: "refused", Error: "certificate: " + err.Error()}, RequestID: id, Source: src, Target: t})
		return
	}
	pre := &bufConn{Conn: c, r: io.MultiReader(bytes.NewReader(hello), br)}
	tc := tls.Server(pre, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		g.audit(wire.Record{Base: audit.Base{Event: "tls_client_abort", Decision: "refused", Code: string(product.CodePinned), Error: err.Error()}, RequestID: id, Source: src, Target: t,
			Rule: "tls:client-abort"})
		return
	}
	_ = c.SetDeadline(time.Time{})
	tbr := bufio.NewReader(tc)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(tbr)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		rh, rp := splitHostPort(req.Host, port)
		if req.Host != "" && (rh != host || rp != port) {
			writeRefusal(tc, newRequestID(), string(product.CodeFloor), "the Host header differs from the CONNECT host", true)
			return
		}
		if !g.serveHTTP(ctx, tc, tbr, req, src, "https", host, port, "mitm") {
			return
		}
	}
}
