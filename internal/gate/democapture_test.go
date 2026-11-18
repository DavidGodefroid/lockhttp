package gate

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// containerConn is a connection that says it arrived on a container's
// network address, as one does in lea's proxy container: sources.json names
// the container by that address.
type containerConn struct {
	net.Conn
	local net.Addr
}

func (c containerConn) LocalAddr() net.Addr { return c.local }

type containerListener struct{ net.Listener }

func (l containerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return containerConn{c, &net.TCPAddr{IP: net.ParseIP("10.89.3.2"), Port: 3130}}, nil
}

const demoCapturePolicy = `
[profiles.default]
hold = "60s"
trusted = ["pkg.go.dev"]
`

// TestDemoCapture is not a test: it writes the gate's half of the README
// demo's capture (scripts/brand/demo-capture/README.md). It is skipped
// unless LOCKHTTP_DEMO_OUT names a directory, and needs curl:
//
//	LOCKHTTP_DEMO_OUT=/tmp/capture go test ./internal/gate -run TestDemoCapture -count=1
//
// It runs the demo's two requests with curl through a gate that reads a
// sources.json as lea writes it, against the tests' fake hub and a stand-in
// upstream, and writes gate.txt (curl's output, then the gate's audit
// records) and ticket.json (the ticket the gate signed for the held POST).
// The fake hub denies the ticket as lox run's n does: no reason, facade tty.
func TestDemoCapture(t *testing.T) {
	out := os.Getenv("LOCKHTTP_DEMO_OUT")
	if out == "" {
		t.Skip("LOCKHTTP_DEMO_OUT is not set")
	}
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	sources := filepath.Join(dir, "sources.json")
	b, _ := json.Marshal(map[string]any{"version": 1,
		"networks": []map[string]string{{"local_ip": "10.89.3.2", "container": "lea-ab12cd34ef", "project": "shop"}},
		"agents": []map[string]string{{"token_sha256": sum([]byte("t3")), "container": "lea-ab12cd34ef", "agent": "dev-3",
			"role": "dev", "parent": "lead-1", "task_id": "t-42", "branch": "feat/ci-report"}}})
	write(sources, b)
	e := newEnvHub(t, demoCapturePolicy, true, func(c *hubclient.Config) { c.Instance = "web" }, nil, func(c *Config) {
		c.Sources = NewSources(sources)
		// The stand-in upstream's certificate is httptest's, not pkg.go.dev's.
		c.UpstreamTLS = &tls.Config{InsecureSkipVerify: true}
	})
	// The senders are confined (sources.json names them): the policy need
	// not allow unconfined ones. Wait for the gate to read it again.
	e.console.pol.Unconfined = false
	time.Sleep(300 * time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = e.gate.Serve(t.Context(), containerListener{ln}) }()
	e.backend("pkg.go.dev", true, http.HandlerFunc(ok))
	e.remap("pkg.go.dev", "443")

	caFile := filepath.Join(dir, "ca.pem")
	write(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.gate.cfg.Certs.(localCerts).c.Cert.Raw}))
	write(filepath.Join(dir, "report.json"), []byte(`{"build":"ok","author":"jean.dupont@example.org"}`))
	var sb strings.Builder
	curl := func(args ...string) {
		cmd := exec.Command("curl", args...)
		cmd.Dir = dir
		proxy := "http://dev-3:t3@" + ln.Addr().String()
		cmd.Env = append(os.Environ(), "HTTPS_PROXY="+proxy, "HTTP_PROXY="+proxy, "CURL_CA_BUNDLE="+caFile, "NO_PROXY=", "no_proxy=")
		o, err := cmd.CombinedOutput()
		fmt.Fprintf(&sb, "$ curl %s\n%s[exit: %v]\n", strings.Join(args, " "), o, err)
	}
	curl("-sS", "-o", "/dev/null", "-w", "%{http_code}\n", "https://pkg.go.dev/net/http")
	go func() {
		tk := e.hub.waitTickets(1)[0]
		j, _ := json.MarshalIndent(tk, "", "  ")
		write(filepath.Join(out, "ticket.json"), j)
		time.Sleep(300 * time.Millisecond)
		e.hub.decideWith(tk, ticket.Denied, "", nil, "", func(d *ticket.Decision) {
			d.Approver = ticket.Approver{ID: "host:uid:1000", Display: "alice"}
		})
	}()
	curl("-sS", "-X", "POST", "https://hooks.example.net/build", "-H", "content-type: application/json", "-d", "@report.json")
	fmt.Fprintf(&sb, "== AUDIT\n%s\n", e.auditText())
	write(filepath.Join(out, "gate.txt"), []byte(sb.String()))
}
