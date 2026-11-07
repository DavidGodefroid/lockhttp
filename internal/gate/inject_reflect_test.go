package gate

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// store keeps the Authorization it got on /api/* and serves it back on
// /log (whole, or the range asked), /log/gz (gzip), /part (a 206 whatever
// was asked) and /ws (a WebSocket). It records the Range headers it got.
type store struct {
	mu     sync.Mutex
	val    string
	ranges []string
	ws     *wsBackend
}

func (s *store) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if a := r.Header.Get("Authorization"); a != "" {
		s.val = a
	}
	s.ranges = append(s.ranges, r.Header.Get("Range")+"|"+r.Header.Get("If-Range"))
	v := "log: " + s.val + " end"
	s.mu.Unlock()
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/"):
		_, _ = io.WriteString(w, "stored")
	case r.URL.Path == "/log":
		w.Header().Set("X-Last", s.val)
		var from, to int
		if n, _ := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &from, &to); n >= 1 {
			if n == 1 || to >= len(v) {
				to = len(v) - 1
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, len(v)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, v[from:to+1])
			return
		}
		_, _ = io.WriteString(w, v)
	case r.URL.Path == "/log/gz":
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Accept", r.Header.Get("Accept-Encoding"))
		_, _ = w.Write(gz(&testing.T{}, v))
	case r.URL.Path == "/log/br":
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, "opaque")
	case r.URL.Path == "/part":
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-9/%d", len(v)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, v[:10])
	case r.URL.Path == "/multipart":
		w.Header().Set("Content-Type", "multipart/byteranges; boundary=x")
		_, _ = io.WriteString(w, v)
	case r.URL.Path == "/ws":
		s.ws.handler(w, r)
	}
}

func scopedStore(t *testing.T) (*env, *store, *http.Client) {
	e := scanEnv(t)
	s := &store{ws: &wsBackend{done: make(chan struct{})}}
	e.backend("scoped", false, http.HandlerFunc(s.handler))
	e.remap("scoped", "8124")
	c := e.client("dev-5", false)
	if resp := do(t, c, "GET", "http://scoped:8124/api/states", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("GET /api/states: %s", resp.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.val != haSecret {
		t.Fatalf("the backend stored %q", s.val)
	}
	return e, s, c
}

// A credential an injected request stored on the target is redacted from
// the responses to the other paths of the same host and port (no
// injection on them), which get the response rules too.
func TestInjectWholeHostResponseRules(t *testing.T) {
	e, _, c := scopedStore(t)
	resp, body := get(t, c, "GET", "http://scoped:8124/log", nil)
	if resp.StatusCode != 200 || strings.Contains(body, haSecret) || strings.Contains(resp.Header.Get("X-Last"), haSecret) {
		t.Fatalf("GET /log gave the stored secret: %s %v %q", resp.Status, resp.Header, body)
	}
	if body != "log: "+strings.Repeat("*", len(haSecret))+" end" {
		t.Fatalf("body %q", body)
	}
	resp, body = get(t, c, "GET", "http://scoped:8124/log/gz", nil)
	if resp.StatusCode != 200 || strings.Contains(body, haSecret) || resp.Header.Get("X-Accept") != "identity" {
		t.Fatalf("gzip: %s %v %q", resp.Status, resp.Header, body)
	}
	resp, _ = get(t, c, "GET", "http://scoped:8124/log/br", nil)
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_INJECT" {
		t.Fatalf("br: %s %v", resp.Status, resp.Header)
	}
	resp, body = get(t, c, "TRACE", "http://scoped:8124/admin", nil)
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_METHOD" || strings.Contains(body, haSecret) {
		t.Fatalf("TRACE: %s %v", resp.Status, resp.Header)
	}
	// Another container (no injection for it at all) gets the same rules.
	resp, body = get(t, e.client("dev-6", false), "GET", "http://scoped:8124/log", nil)
	if strings.Contains(body, haSecret) || strings.Contains(fmt.Sprint(resp.Header), haSecret) {
		t.Fatalf("another container got the stored secret: %s %q", resp.Status, body)
	}
	// No path of the host upgrades to a WebSocket.
	e.hub.answerAll(ticket.Approved, "")
	conn := rawProxy(t, e)
	fmt.Fprintf(conn, "GET http://scoped:8124/ws HTTP/1.1\r\nHost: scoped:8124\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s\r\n", agentProxyAuth())
	wresp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || wresp.StatusCode != 403 || wresp.Header.Get("X-LockHTTP-Code") != "E_INJECT" {
		t.Fatalf("upgrade: %v %v", err, wresp)
	}
	if a := e.auditText(); strings.Contains(a, haSecret) || !strings.Contains(a, "redacted the injected secret ha-token from the response") {
		t.Fatalf("audit:\n%s", a)
	}
}

// Range and If-Range never reach an injected host (two ranges would join
// the halves of a redacted value), and a partial response is refused.
func TestInjectRangeStripped(t *testing.T) {
	e, s, c := scopedStore(t)
	var joined string
	for _, r := range []string{"bytes=0-23", "bytes=24-"} {
		resp, body := get(t, c, "GET", "http://scoped:8124/log", http.Header{"Range": {r}, "If-Range": {`"etag"`}})
		if resp.StatusCode != 200 {
			t.Fatalf("Range %s: %s", r, resp.Status)
		}
		joined += body
	}
	if strings.Contains(joined, haSecret) || strings.Contains(joined, haSecret[:12]) || strings.Contains(joined, haSecret[12:]) {
		t.Fatalf("the ranges gave the secret: %q", joined)
	}
	s.mu.Lock()
	for _, r := range s.ranges {
		if r != "|" {
			t.Errorf("the backend got Range|If-Range %q", r)
		}
	}
	s.mu.Unlock()
	for _, p := range []string{"/part", "/multipart"} {
		resp, body := get(t, c, "GET", "http://scoped:8124"+p, nil)
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_INJECT" || strings.Contains(body, haSecret[:10]) {
			t.Fatalf("%s: %s %v %q", p, resp.Status, resp.Header, body)
		}
	}
	if a := e.auditText(); !strings.Contains(a, "the response is partial") {
		t.Fatalf("audit:\n%s", a)
	}
}

// A value in the host (absolute URL, Host header, CONNECT authority, any
// case, split by dots) or in a header name is refused first: before the
// floor, the hub's DNS check and the hub, with none of it in the audit.
func TestInjectLeakInHostAndHeaderNames(t *testing.T) {
	e := scanEnv(t)
	var mu sync.Mutex
	var resolved []string
	e.gate.cfg.Hub.Nets = []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")}
	e.gate.cfg.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		resolved = append(resolved, host)
		mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	var s seen
	e.backend("trusted.test", false, http.HandlerFunc(s.handler))
	e.remap("trusted.test", "80")
	c := e.client("dev-5", false)
	upper := strings.ToUpper(haSecret)
	dotted := haSecret[:7] + "." + haSecret[7:]
	for _, u := range []string{"http://" + haSecret + ".example.com/", "http://" + upper + ".example.com/x", "http://" + dotted + ".example.com/"} {
		resp := do(t, c, "GET", u, nil, "")
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
			t.Errorf("%s: %s %v", u, resp.Status, resp.Header)
		}
	}
	resp := do(t, c, "GET", "http://trusted.test/", http.Header{"X-" + haSecret: {"1"}}, "")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Errorf("header name: %s %v", resp.Status, resp.Header)
	}
	if s.last() != nil {
		t.Error("the backend got the request with the header name")
	}
	// CONNECT.
	conn := rawProxy(t, e)
	fmt.Fprintf(conn, "CONNECT %s.example.com:443 HTTP/1.1\r\nHost: %s.example.com:443\r\n%s\r\n", upper, upper, agentProxyAuth())
	cresp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || cresp.StatusCode != 403 || cresp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Errorf("CONNECT: %v %v", err, cresp)
	}
	mu.Lock()
	for _, h := range resolved {
		if strings.Contains(strings.ToLower(strings.ReplaceAll(h, ".", "")), haSecret) {
			t.Errorf("the gate resolved %q", h)
		}
	}
	mu.Unlock()
	a := e.auditText()
	if strings.Contains(strings.ToLower(strings.ReplaceAll(a, ".", "")), haSecret) {
		t.Fatalf("the audit holds the secret:\n%s", a)
	}
	if strings.Count(a, `"rule":"secret:injected"`) != 5 {
		t.Fatalf("want 5 secret:injected refusals:\n%s", a)
	}
	if len(e.Calls()) != 0 {
		t.Fatal("a refused request reached the hub")
	}
}
