package gate

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// scanPolicy streams bodies past 1 KiB to trusted.test/up, and limits an
// injection to GET /api/*.
const scanPolicy = injectPolicy + `
[[profiles.default.inject]]
id         = "scoped"
host       = "scoped"
port       = 8124
header     = "Authorization"
credential = "ha-token"
methods    = ["GET"]
paths      = ["/api/*"]

[[profiles.default.internal_hosts]]
host  = "scoped"
ports = [8124]
read  = true

[[profiles.default.rules]]
id      = "up"
host    = "trusted.test"
methods = ["POST"]
path    = "/up"
verdict = "free"
`

func scanEnv(t *testing.T) *env {
	path := writeSecrets(t, map[string]string{"ha-token": haSecret, "api-key": apiSecret})
	conf := strings.Replace(scanPolicy, "hold = \"2s\"", "hold = \"2s\"\nbuffer_limit = \"1KiB\"", 1)
	return newEnv(t, conf, false, func(c *Config) { c.Secrets = NewSecrets(path) })
}

// bodies records the bodies the backend received, whole or cut.
type bodies struct {
	mu sync.Mutex
	b  [][]byte
}

func (s *bodies) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.b = append(s.b, b)
	s.mu.Unlock()
	_, _ = io.WriteString(w, "ok")
}

func (s *bodies) any(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.b {
		if bytes.Contains(b, []byte(sub)) {
			return true
		}
	}
	return false
}

// A body over the buffer limit is scanned as it streams: the value past
// the held prefix aborts the request before it goes out.
func TestInjectStreamedBodyLeak(t *testing.T) {
	e := scanEnv(t)
	var s bodies
	e.backend("trusted.test", false, http.HandlerFunc(s.handler))
	e.remap("trusted.test", "80")
	c := e.client("dev-5", false)
	clean := strings.Repeat("a", 64<<10)
	if resp := do(t, c, "POST", "http://trusted.test/up", http.Header{"Content-Type": {"text/plain"}}, clean); resp.StatusCode != 200 {
		t.Fatalf("clean streamed body: %s", resp.Status)
	}
	for name, body := range map[string]string{
		"raw":    strings.Repeat("a", 40<<10) + haSecret + strings.Repeat("b", 4<<10),
		"hex":    strings.Repeat("a", 40<<10) + hex.EncodeToString([]byte(apiSecret)),
		"base64": strings.Repeat("a", 40<<10) + "x" + base64.StdEncoding.EncodeToString([]byte("q"+haSecret+"r")),
	} {
		req, _ := http.NewRequest("POST", "http://trusted.test/up", strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		resp, err := c.Do(req)
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
				t.Errorf("%s: %s %v", name, resp.Status, resp.Header)
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	if s.any(haSecret[:len(haSecret)-1]) || s.any(hex.EncodeToString([]byte(apiSecret))[:20]) {
		t.Fatal("the backend received an injected secret from a streamed body")
	}
	if a := e.auditText(); !strings.Contains(a, `"rule":"secret:injected"`) || strings.Contains(a, haSecret) {
		t.Fatalf("audit:\n%s", a)
	}
}

// A compressed body is decoded to be scanned; one the gate cannot decode
// is refused while it holds secrets.
func TestInjectEncodedBodyLeak(t *testing.T) {
	e := scanEnv(t)
	var s bodies
	e.backend("trusted.test", false, http.HandlerFunc(s.handler))
	e.remap("trusted.test", "80")
	c := e.client("dev-5", false)
	h := http.Header{"Content-Type": {"text/plain"}, "Content-Encoding": {"gzip"}}
	if resp := do(t, c, "POST", "http://trusted.test/up", h, string(gz(t, "clean"))); resp.StatusCode != 200 {
		t.Fatalf("clean gzip: %s", resp.Status)
	}
	resp := do(t, c, "POST", "http://trusted.test/up", h, string(gz(t, "k="+haSecret)))
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("gzip leak: %s %v", resp.Status, resp.Header)
	}
	resp = do(t, c, "POST", "http://trusted.test/up", http.Header{"Content-Type": {"text/plain"}, "Content-Encoding": {"br"}}, "opaque")
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("br: %s %v", resp.Status, resp.Header)
	}
	if a := e.auditText(); !strings.Contains(a, `"rule":"secret:unscannable"`) {
		t.Fatalf("audit:\n%s", a)
	}
	if len(s.b) != 1 {
		t.Fatalf("the backend got %d bodies, want 1", len(s.b))
	}
}

// echo reflects the Authorization it got: in a header, the body
// (gzip-encoded on /gz whatever the request accepted) and a redirect.
func echo(w http.ResponseWriter, r *http.Request) {
	a := r.Header.Get("Authorization")
	switch r.URL.Path {
	case "/api/gz":
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Accept", r.Header.Get("Accept-Encoding"))
		_, _ = w.Write(gz(&testing.T{}, "you sent "+a))
	case "/api/br":
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, "opaque")
	default:
		w.Header().Set("X-Echo", a)
		w.Header().Set("X-Echo-B64", base64.StdEncoding.EncodeToString([]byte(a)))
		w.Header().Set("X-Max-Forwards", r.Header.Get("Max-Forwards"))
		fmt.Fprintf(w, "you sent %s", a)
	}
}

func get(t *testing.T, c *http.Client, method, u string, h http.Header) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	for k, vs := range h {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// An injected credential the target reflects never reaches the agent: it
// is redacted from the response's headers and body (decoded first), and
// TRACE is refused.
func TestInjectReflectionRedacted(t *testing.T) {
	e := scanEnv(t)
	e.backend("homeassistant", false, http.HandlerFunc(echo))
	e.remap("homeassistant", "8123")
	c := e.client("dev-5", false)
	resp, body := get(t, c, "GET", "http://homeassistant:8123/api/x", http.Header{"Max-Forwards": {"0"}})
	if resp.StatusCode != 200 {
		t.Fatalf("status %s", resp.Status)
	}
	dump := fmt.Sprint(resp.Header) + body
	if strings.Contains(dump, haSecret) || strings.Contains(dump, base64.StdEncoding.EncodeToString([]byte("Bearer " + haSecret))[12:]) {
		t.Fatalf("the agent got the injected secret: %s", dump)
	}
	if !strings.Contains(body, "you sent Bearer ****") || resp.Header.Get("X-Max-Forwards") != "" {
		t.Fatalf("body %q, Max-Forwards %q", body, resp.Header.Get("X-Max-Forwards"))
	}
	resp, body = get(t, c, "GET", "http://homeassistant:8123/api/gz", nil)
	if resp.StatusCode != 200 || strings.Contains(body, haSecret) || !strings.Contains(body, "you sent Bearer ****") {
		t.Fatalf("gzip echo: %s %q", resp.Status, body)
	}
	if resp.Header.Get("X-Accept") != "identity" {
		t.Fatalf("the gate did not ask for an unencoded response: %q", resp.Header.Get("X-Accept"))
	}
	resp, _ = get(t, c, "GET", "http://homeassistant:8123/api/br", nil)
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_INJECT" {
		t.Fatalf("br response: %s %v", resp.Status, resp.Header)
	}
	for _, m := range []string{"TRACE", "TRACK"} {
		resp, body = get(t, c, m, "http://homeassistant:8123/api/x", nil)
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_METHOD" || strings.Contains(body, haSecret) {
			t.Fatalf("%s: %s %v", m, resp.Status, resp.Header)
		}
	}
	a := e.auditText()
	if !strings.Contains(a, "redacted the injected secret ha-token from the response") || !strings.Contains(a, `"rule":"inject:trace"`) || strings.Contains(a, haSecret) {
		t.Fatalf("audit:\n%s", a)
	}
}

// An injection with methods and paths applies to those only.
func TestInjectMethodsPaths(t *testing.T) {
	e := scanEnv(t)
	var s seen
	e.backend("scoped", false, http.HandlerFunc(s.handler))
	e.remap("scoped", "8124")
	c := e.client("dev-5", false)
	do(t, c, "GET", "http://scoped:8124/api/states", nil, "")
	if got := s.last().Get("Authorization"); got != haSecret {
		t.Fatalf("GET /api/states: %q", got)
	}
	do(t, c, "GET", "http://scoped:8124/admin", nil, "")
	if got := s.last().Get("Authorization"); got != "" {
		t.Fatalf("GET /admin got the credential")
	}
	e.hub.answerAll(ticket.Approved, "")
	if resp := do(t, c, "POST", "http://scoped:8124/api/states", http.Header{"Content-Type": {"application/json"}}, "{}"); resp.StatusCode != 200 {
		t.Fatalf("POST: %s", resp.Status)
	}
	if got := s.last().Get("Authorization"); got != "" {
		t.Fatalf("POST got the credential")
	}
	if a := e.auditText(); !strings.Contains(a, "inject scoped skipped: the policy does not name GET /admin") {
		t.Fatalf("audit:\n%s", a)
	}
}

// rawProxy opens a connection to the gate as dev-5.
func rawProxy(t *testing.T, e *env) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

func agentProxyAuth() string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("dev-5:tok-dev-5")) + "\r\n"
}

// wsBackend accepts a WebSocket upgrade and records the raw bytes the
// client's frames carried after it, and the extensions it was offered.
type wsBackend struct {
	mu   sync.Mutex
	got  bytes.Buffer
	ext  string
	done chan struct{}
}

func (b *wsBackend) handler(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	b.ext = r.Header.Get("Sec-Websocket-Extensions")
	b.mu.Unlock()
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
	_ = brw.Flush()
	buf := make([]byte, 4096)
	for {
		n, err := brw.Read(buf)
		b.mu.Lock()
		b.got.Write(buf[:n])
		b.mu.Unlock()
		if err != nil {
			close(b.done)
			return
		}
	}
}

// A WebSocket's frames are unmasked and scanned: the frame carrying the
// value is not sent and the connection closes. An injected request may
// not upgrade.
func TestWebSocketFramesScanned(t *testing.T) {
	e := scanEnv(t)
	wb := &wsBackend{done: make(chan struct{})}
	e.backend("trusted.test", false, http.HandlerFunc(wb.handler))
	e.remap("trusted.test", "80")
	e.hub.answerAll(ticket.Approved, "")
	c := rawProxy(t, e)
	fmt.Fprintf(c, "GET http://trusted.test/ws HTTP/1.1\r\nHost: trusted.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n%s\r\n", agentProxyAuth())
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v\n%s", err, resp, e.auditText())
	}
	k := [4]byte{9, 8, 7, 6}
	_, _ = c.Write(wsFrame([]byte("hello"), k))
	time.Sleep(100 * time.Millisecond)
	_, _ = c.Write(wsFrame([]byte("token "+haSecret), k))
	select {
	case <-wb.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the gate did not close the WebSocket")
	}
	wb.mu.Lock()
	got, ext := wb.got.Bytes(), wb.ext
	wb.mu.Unlock()
	if !bytes.Equal(got, wsFrame([]byte("hello"), k)) {
		t.Fatalf("the backend got %d bytes, want the first frame only", len(got))
	}
	if ext != "" {
		t.Fatalf("the gate forwarded the extension offer %q", ext)
	}
	if a := e.auditText(); !strings.Contains(a, "a WebSocket frame carries the value of the secret ha-token") {
		t.Fatalf("audit:\n%s", a)
	}

	// An injected request does not upgrade.
	e.backend("homeassistant", false, http.HandlerFunc(wb.handler))
	e.remap("homeassistant", "8123")
	c2 := rawProxy(t, e)
	fmt.Fprintf(c2, "GET http://homeassistant:8123/api/websocket HTTP/1.1\r\nHost: homeassistant:8123\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s\r\n", agentProxyAuth())
	resp, err = http.ReadResponse(bufio.NewReader(c2), nil)
	if err != nil || resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_INJECT" {
		t.Fatalf("injected upgrade: %v %v", err, resp)
	}
}

// A plain-text CONNECT tunnel is scanned as it streams.
func TestTunnelScanned(t *testing.T) {
	e := scanEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got bytes.Buffer
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			mu.Lock()
			got.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				close(done)
				return
			}
		}
	}()
	e.backends["trusted.test"] = ln.Addr().String()
	e.remap("trusted.test", "80")
	c := rawProxy(t, e)
	fmt.Fprintf(c, "CONNECT trusted.test:80 HTTP/1.1\r\nHost: trusted.test:80\r\n%s\r\n", agentProxyAuth())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", err, resp)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: trusted.test\r\n\r\n")
	time.Sleep(200 * time.Millisecond)
	_, _ = io.WriteString(c, "X: "+haSecret+"\r\n")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the gate did not close the tunnel")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(got.String(), "GET / HTTP/1.1") || strings.Contains(got.String(), haSecret) {
		t.Fatalf("the backend got %q", got.String())
	}
	if a := e.auditText(); !strings.Contains(a, "the tunnel carries the value of the secret ha-token") {
		t.Fatalf("audit:\n%s", a)
	}
}
