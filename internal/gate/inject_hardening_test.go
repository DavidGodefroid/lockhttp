package gate

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

// pathSeen records the Authorization and the raw path the backend got.
type pathSeen struct {
	mu   sync.Mutex
	auth map[string]string
}

func (s *pathSeen) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.auth == nil {
		s.auth = map[string]string{}
	}
	s.auth[r.RequestURI] = r.Header.Get("Authorization")
	s.mu.Unlock()
	_, _ = io.WriteString(w, "ok")
}

func (s *pathSeen) get(uri string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.auth[uri]
	return a, ok
}

// rawGet sends one request line as is (no client cleans its path) and
// returns the response.
func rawGet(t *testing.T, e *env, method, uri, host string) *http.Response {
	t.Helper()
	c := rawProxy(t, e)
	fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", method, uri, host, agentProxyAuth())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%s %s: %v", method, uri, err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp
}

// An injection limited to /api/* adds nothing to a path a target may
// resolve outside it (a dot segment, encoded or not, an encoded slash,
// dots with a space or a NUL, overlong UTF-8, a fullwidth dot):
// the request goes out as the agent wrote it, without the credential.
func TestInjectAmbiguousPathNotInjected(t *testing.T) {
	e := scanEnv(t)
	var s pathSeen
	e.backend("scoped", false, http.HandlerFunc(s.handler))
	e.remap("scoped", "8124")
	for _, p := range []string{"/api/../admin", "/api/%2e%2e/admin", "/api/%2E%2E%2Fadmin",
		"/api/..%20/admin", "/api/.%20/admin", "/api/..%00/admin", "/api/...", "/api/..%3f/admin",
		"/api/%c0%ae%c0%ae/admin", "/api/%e0%80%ae%e0%80%ae/admin", "/api/%ef%bc%8e%ef%bc%8e/admin", "/api/%ff/x", "/api/x%41",
		"/api/..%cd%8f/admin", "/api/..%ef%b8%8f/admin", "/api/..%e3%85%a4/admin", "/api/..%e1%85%9f/admin",
		"/api/..%cc%b8/admin", "/api/.%cc%81./admin", "/api/%cc%81../admin"} {
		resp := rawGet(t, e, "GET", "http://scoped:8124"+p, "scoped:8124")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %s", p, resp.Status)
		}
		a, ok := s.get(p)
		if !ok {
			t.Fatalf("%s: the backend did not get the path as sent", p)
		}
		if a != "" {
			t.Fatalf("%s reached the backend with the credential", p)
		}
	}
	for _, p := range []string{"/api/states", "/api/caf%C3%A9", "/api/a%3Ab", "/api/%ce%b1%cc%81"} {
		resp := rawGet(t, e, "GET", "http://scoped:8124"+p, "scoped:8124")
		if a, _ := s.get(p); resp.StatusCode != 200 || a != haSecret {
			t.Fatalf("%s: %s, credential %v", p, resp.Status, a == haSecret)
		}
	}
	if a := e.auditText(); !strings.Contains(a, "inject scoped skipped: the path is not canonical") || strings.Contains(a, haSecret) {
		t.Fatalf("audit:\n%s", a)
	}
}

// TRACE and TRACK to an injected host are refused in any case of the
// method: none reaches the target with the credential.
func TestInjectTraceAnyCase(t *testing.T) {
	e := scanEnv(t)
	var mu sync.Mutex
	var reached []string
	e.backend("homeassistant", false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Method+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	e.remap("homeassistant", "8123")
	c := e.client("dev-5", false)
	for _, m := range []string{"trace", "Trace", "tRACE", "track", "Track"} {
		resp, body := get(t, c, m, "http://homeassistant:8123/api/x", nil)
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_METHOD" || strings.Contains(body, haSecret) {
			t.Fatalf("%s: %s %v", m, resp.Status, resp.Header)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reached) != 0 {
		t.Fatalf("the target got %q", reached)
	}
}

// Every scanner of what the agent sends accepts the same forms: a value
// escaped in a way findDecoded decodes (arbitrary escapes, a stray '%',
// twice escaped) is found by the streamed body's scan, the decoded body's
// scan, a WebSocket's frames and the response redaction too.
func TestScannersAcceptSameForms(t *testing.T) {
	fs := testForms()
	escAll := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "%%%02x", s[i])
		}
		return b.String()
	}
	forms := map[string]string{
		"every byte escaped":     escAll(haSecret),
		"upper escapes":          strings.ToUpper(escAll(haSecret)),
		"escaped with stray %":   "100% " + escAll(haSecret) + " %zz",
		"escaped twice":          strings.ReplaceAll(escAll(haSecret), "%", "%25"),
		"hex escaped":            escAll(hex.EncodeToString([]byte(haSecret))),
		"partly escaped, plus +": "a+b+" + strings.Replace(haSecret, "-", "%2D", 2),
	}
	for name, f := range forms {
		data := "head " + strings.Repeat("x", 5000) + f + " tail"
		if n, ok := fs.findDecoded([]byte(data)); !ok || n != "ha-token" {
			t.Errorf("%s: findDecoded missed it", name)
		}
		sr := &scanReader{r: iotest.OneByteReader(strings.NewReader(data)), fs: fs}
		got, err := io.ReadAll(sr)
		if err == nil || len(sr.found) == 0 {
			t.Errorf("%s: the streamed scan missed it", name)
		} else if bytes.Contains(got, []byte(f[:len(f)-1])) {
			t.Errorf("%s: the streamed scan let it out whole but its last byte", name)
		}
		if n, why := encodedLeak("gzip", gz(t, data), false, fs); n != "ha-token" || why != "" {
			t.Errorf("%s: the decoded body's scan missed it (%q %q)", name, n, why)
		}
		var in, out bytes.Buffer
		half := len(f) / 2
		in.Write(wsFrame([]byte(data[:5005+half]), [4]byte{9, 8, 7, 6}))
		in.Write(wsFrame([]byte(data[5005+half:]), [4]byte{1, 2, 3, 4}))
		if _, leak, _ := copyWebSocket(&out, &in, fs, 1<<20); leak != "ha-token" {
			t.Errorf("%s: the WebSocket scan missed it", name)
		}
		var sink bytes.Buffer
		if _, leak := copyScanned(&sink, iotest.HalfReader(strings.NewReader(data)), fs); leak != "ha-token" {
			t.Errorf("%s: the tunnel scan missed it", name)
		}
		rr := &scanReader{r: iotest.OneByteReader(strings.NewReader(data)), fs: fs, redact: true}
		red, err := io.ReadAll(rr)
		if err != nil || len(red) != len(data) {
			t.Fatalf("%s: redact: %v, %d bytes for %d", name, err, len(red), len(data))
		}
		if n, ok := fs.findDecoded(red); ok {
			t.Errorf("%s: the redacted response still holds %s: %q", name, n, red[5000:])
		}
		if !strings.HasPrefix(string(red), "head xxx") || !strings.HasSuffix(string(red), " tail") {
			t.Errorf("%s: redacted the wrong bytes: %q", name, red[5000:])
		}
	}
	// A clean stream with escapes passes whole, unchanged.
	clean := strings.Repeat("a%20b+c%zz ", 3000)
	if _, ok := fs.findDecoded([]byte(clean)); ok {
		t.Fatal("a clean body matched")
	}
	sr := &scanReader{r: iotest.HalfReader(strings.NewReader(clean)), fs: fs, redact: true}
	if got, err := io.ReadAll(sr); err != nil || string(got) != clean {
		t.Fatalf("clean stream: %v", err)
	}
}

// findFold is linear: a name built to make a recursive decoder branch at
// every escape is scanned in bounded time, and one over the length limit
// is not scanned at all.
func TestFindFoldPathologicalBounded(t *testing.T) {
	fs := testForms()
	// "%2525...25" loses one "25" per round: the recursive decoder took
	// 2^n steps on it (7.6s at n=22), a 1 KiB name is far worse.
	inputs := []string{
		"%" + strings.Repeat("25", 500),
		"%" + strings.Repeat("2.5", 340),
		strings.Repeat("%25", 340),
		strings.Repeat("%2525.", 170),
		strings.Repeat("%2e%25", 170),
		"X-" + strings.Repeat("%252E", 200),
	}
	start := time.Now()
	for _, in := range inputs {
		if len(in) > maxFoldName {
			t.Fatalf("input of %d bytes", len(in))
		}
		if _, ok := fs.findFold([]byte(in)); ok {
			t.Errorf("%q...: found", in[:12])
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("pathological names took %v", d)
	}
	// The value is still found through the rounds (twice escaped, dots).
	if n, ok := fs.findFold([]byte(strings.ReplaceAll(strings.ReplaceAll(haSecret, "-", "%252D"), "0", ".0") + ".example.com")); !ok || n != "ha-token" {
		t.Fatal("a twice-escaped value was not found")
	}
	if n, ok := fs.findFold([]byte(strings.Repeat("a", maxFoldName+1))); !ok || n != "" {
		t.Fatalf("an over-long name was scanned: %q %v", n, ok)
	}
	s := NewSecrets(writeSecrets(t, map[string]string{"ha-token": haSecret}))
	if _, why := s.LeakNames([]string{strings.Repeat("a", maxHostName+1)}, nil); why == "" {
		t.Fatal("an over-long host was scanned")
	}
	if _, why := s.LeakNames([]string{"ok.example.com"}, []string{"X-" + strings.Repeat("a", maxFoldName)}); why == "" {
		t.Fatal("an over-long header name was scanned")
	}
	if n, why := s.LeakNames([]string{"ok.example.com"}, []string{"X-" + haSecret}); n != "ha-token" || why != "" {
		t.Fatalf("LeakNames: %q %q", n, why)
	}
	if n, why := (&Secrets{}).LeakNames([]string{strings.Repeat("a", 5000)}, nil); n != "" || why != "" {
		t.Fatal("without secrets, names are not limited")
	}
}

// Through the gate: a pathological header name is answered quickly, an
// over-long host or header name is refused unscanned (before
// authentication too, where only the audit's host is at stake).
func TestGateNameLimits(t *testing.T) {
	e := scanEnv(t)
	var s seen
	e.backend("homeassistant", false, http.HandlerFunc(s.handler))
	e.remap("homeassistant", "8123")
	c := e.client("dev-5", false)
	start := time.Now()
	resp, _ := get(t, c, "GET", "http://homeassistant:8123/api/x", http.Header{"X-%" + strings.Repeat("25", 500): {"1"}})
	if resp.StatusCode != 200 {
		t.Fatalf("pathological header name: %s %v", resp.Status, resp.Header)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("pathological header name took %v", d)
	}
	resp, _ = get(t, c, "GET", "http://homeassistant:8123/api/x", http.Header{"X-" + strings.Repeat("a", maxFoldName): {"1"}})
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("over-long header name: %s %v", resp.Status, resp.Header)
	}
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".eeeeeeeeee" + ".example.com"
	r := rawGet(t, e, "GET", "http://"+long+"/", long)
	if r.StatusCode != 403 || r.Header.Get("X-LockHTTP-Code") != "E_SECRET_EGRESS" {
		t.Fatalf("over-long host: %s %v", r.Status, r.Header)
	}
	if a := e.auditText(); !strings.Contains(a, `"rule":"secret:unscannable"`) || !strings.Contains(a, "a header name longer than 1024 bytes") ||
		!strings.Contains(a, "a host longer than 263 bytes") {
		t.Fatalf("audit:\n%s", a)
	}
}
