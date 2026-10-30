package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// fakeHub is lockhub's lock API as hubclient speaks it: it keeps the
// tickets pushed to it and serves the decisions a test makes.
type fakeHub struct {
	t       *testing.T
	lockPub ed25519.PublicKey
	key     ed25519.PrivateKey // the hub's

	mu        sync.Mutex
	tickets   []*ticket.Ticket
	raw       map[string][]byte // the signed tickets, by id
	decisions []json.RawMessage // decisions[i] has seq i+1
	ids       []string
	consumed  map[string]bool
	withdraws map[string]bool
}

func (h *fakeHub) withdrawn(id string) bool { h.mu.Lock(); defer h.mu.Unlock(); return h.withdraws[id] }

func newFakeHub(t *testing.T, lockPub ed25519.PublicKey) (*fakeHub, *httptest.Server) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHub{t: t, lockPub: lockPub, key: key, consumed: map[string]bool{}, withdraws: map[string]bool{}, raw: map[string][]byte{}}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return h, s
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Lock-Sig") == "" {
		http.Error(w, `{"error":"unsigned"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/tickets":
		b, _ := io.ReadAll(r.Body)
		t, err := ticket.VerifyTicket(h.lockPub, b)
		if err != nil {
			http.Error(w, `{"error":"bad ticket"}`, http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.tickets = append(h.tickets, t)
		h.raw[t.ID] = b
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"ticket": t.ID})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/decisions":
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		deadline := time.Now().Add(200 * time.Millisecond)
		for {
			h.mu.Lock()
			n := len(h.decisions)
			if n > since || time.Now().After(deadline) {
				var out []map[string]any
				for i := since; i < n; i++ {
					out = append(out, map[string]any{"seq": i + 1, "ticket": h.ids[i], "decision": h.decisions[i]})
				}
				h.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{"decisions": out, "cursor": max(n, since)})
				return
			}
			h.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/consumed"):
		h.mu.Lock()
		h.consumed[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/tickets/"), "/consumed")] = true
		h.mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/withdraw"):
		h.mu.Lock()
		h.withdraws[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/tickets/"), "/withdraw")] = true
		h.mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	default:
		_, _ = io.WriteString(w, "{}")
	}
}

func (h *fakeHub) Tickets() []*ticket.Ticket {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*ticket.Ticket(nil), h.tickets...)
}

// waitTickets waits for n tickets.
func (h *fakeHub) waitTickets(n int) []*ticket.Ticket {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ts := h.Tickets(); len(ts) >= n {
			return ts
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("the hub got %d tickets, want %d", len(h.Tickets()), n)
	return nil
}

// decide files a decision on t, signed with key (the hub's when nil),
// for instance (t's when "").
func (h *fakeHub) decide(t *ticket.Ticket, o ticket.Outcome, reason string, key ed25519.PrivateKey, instance string) *ticket.Decision {
	h.t.Helper()
	return h.decideWith(t, o, reason, key, instance, nil)
}

// decideWith is decide with mod applied before the hub signs (a device's
// assertion, another facade).
func (h *fakeHub) decideWith(t *ticket.Ticket, o ticket.Outcome, reason string, key ed25519.PrivateKey, instance string, mod func(*ticket.Decision)) *ticket.Decision {
	h.t.Helper()
	if key == nil {
		key = h.key
	}
	if instance == "" {
		instance = t.Source.Instance
	}
	d := &ticket.Decision{V: ticket.Version, Ticket: t.ID, Instance: instance, KeyID: t.Source.KeyID, PlanHash: t.PlanHash,
		Decision: o, Reason: reason, Approver: ticket.Approver{ID: "u1", Display: "Human"}, Facade: "tty",
		At: time.Now().UTC().Truncate(time.Millisecond), Nonce: ticket.NewNonce(), HubKeyID: ticket.KeyID(key.Public().(ed25519.PublicKey))}
	if mod != nil {
		mod(d)
	}
	if err := d.Sign(key); err != nil {
		h.t.Fatal(err)
	}
	h.file(t.ID, d)
	return d
}

// file serves d (again) as the next decision on ticket id.
func (h *fakeHub) file(id string, d *ticket.Decision) {
	b, err := ticket.Canonical(d)
	if err != nil {
		h.t.Fatal(err)
	}
	h.mu.Lock()
	h.decisions = append(h.decisions, b)
	h.ids = append(h.ids, id)
	h.mu.Unlock()
}

// hubEnv is a gate in hub mode, its fake hub and its plan store.
func hubEnv(t *testing.T, conf string, mutate func(*Hub)) (*env, *fakeHub) {
	t.Helper()
	return hubEnvWith(t, conf, nil, mutate)
}

// hubEnvWith is hubEnv with the hub client's configuration changed by
// config (pinned devices).
func hubEnvWith(t *testing.T, conf string, config func(*hubclient.Config), mutate func(*Hub)) (*env, *fakeHub) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fh, srv := newFakeHub(t, pub)
	dir := t.TempDir()
	st, err := plans.Open(filepath.Join(dir, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := hubclient.Config{URL: srv.URL, Instance: "egress", Key: key, HubKey: fh.key.Public().(ed25519.PublicKey),
		StateFile: filepath.Join(dir, "hub-state.json")}
	if config != nil {
		config(&cfg)
	}
	c, err := hubclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{Client: c, Plans: st, Poll: 20 * time.Millisecond}
	if mutate != nil {
		mutate(h)
	}
	// Runs after newEnv's cleanup stopped the gate, before the hub and the
	// plans directory go: the stopped asks withdraw their tickets first.
	var g *Gate
	t.Cleanup(func() {
		select {
		case <-g.Stopped():
		case <-time.After(10 * time.Second):
			t.Error("the gate did not stop")
		}
		// Before the plans directory goes (Windows refuses to remove a
		// locked file).
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	e := newEnv(t, conf, true, func(cfg *Config) { cfg.Hub = h; cfg.Log = testLog{t} })
	g = e.gate
	// The console is never asked in hub mode.
	e.console.answer = func(p wire.ApproveParams) (wire.ApproveResult, error) {
		t.Errorf("the console was asked about %s %s", p.Method, p.Host)
		return wire.ApproveResult{}, &Refusal{Code: "E_DENIED"}
	}
	return e, fh
}

func (e *env) waitIdle() {
	deadline := time.Now().Add(3 * time.Second)
	for e.gate.queue.Pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) post(c *http.Client, body string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest("POST", "https://example.com/up", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

var hubTestPolicy = strings.Replace(testPolicy, `hold = "2s"`, `hold = "1s"`, 1)

// A held request becomes a ticket; once the hub approves it, the retried
// request passes once, and a further retry is a new ticket.
func TestHubPendingThenSingleUse(t *testing.T) {
	e, fh := hubEnv(t, hubTestPolicy, nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	if r := e.post(c, `{"to":"jean.dupont@example.org"}`); r.Header.Get("X-LockHTTP-Code") != "E_PENDING" {
		t.Fatalf("hold: %s %v", r.Status, r.Header)
	}
	tk := fh.waitTickets(1)[0]
	if tk.Source.Lock != "lockhttp" || tk.Source.Instance != "egress" || tk.Risk != ticket.RiskWrite || !tk.Flags.NeverAuto {
		t.Errorf("ticket: %+v", tk)
	}
	screen := strings.Join(append([]string{tk.Screen.Header}, tk.Screen.Body...), "\n")
	if !strings.Contains(screen, "POST example.com") || strings.Contains(screen, "jean.dupont@example.org") {
		t.Errorf("screen not masked or incomplete:\n%s", screen)
	}
	fh.decide(tk, ticket.Approved, "", nil, "")
	e.waitIdle()
	if r := e.post(c, `{"to":"jean.dupont@example.org"}`); r.StatusCode != 200 {
		t.Fatalf("approved request refused: %s %v", r.Status, r.Header)
	}
	if r := e.post(c, `{"to":"jean.dupont@example.org"}`); r.Header.Get("X-LockHTTP-Code") != "E_PENDING" {
		t.Fatalf("the pass was used twice: %s %v", r.Status, r.Header)
	}
	if n := len(fh.waitTickets(2)); n != 2 {
		t.Fatalf("tickets %d, want a new one", n)
	}
	fh.mu.Lock()
	consumed := fh.consumed[tk.ID]
	fh.mu.Unlock()
	if !consumed {
		t.Error("the hub was not told the ticket was consumed")
	}
	// The decision is audited with its ticket, then the request it lets
	// through as the single-use pass.
	audit := e.auditText()
	if !hasRecord(audit, map[string]string{"event": "approved", "approval": "hub", "ticket": tk.ID, "facade": "tty"}) || !strings.Contains(audit, `"approver":{"id":"u1","display":"Human"}`) || !strings.Contains(audit, `"hub_sig":"`) ||
		!hasRecord(audit, map[string]string{"event": "free", "rule": "grant:once"}) {
		t.Errorf("audit lacks the hub approval:\n%s", audit)
	}
}

// A decision delivered again, one signed by another key and one for
// another instance grant nothing.
func TestHubReplayAndForgeryRefused(t *testing.T) {
	e, fh := hubEnv(t, hubTestPolicy, nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	e.post(c, `{"a":1}`)
	first := fh.waitTickets(1)[0]
	d := fh.decide(first, ticket.Approved, "", nil, "")
	e.waitIdle()
	if r := e.post(c, `{"a":1}`); r.StatusCode != 200 {
		t.Fatalf("approved request refused: %s", r.Status)
	}
	// The same request again: a new ticket. The hub replays the old
	// decision, then forges two.
	e.post(c, `{"a":1}`)
	second := fh.waitTickets(2)[1]
	fh.file(second.ID, d)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	fh.decide(second, ticket.Approved, "", other, "")
	fh.decide(second, ticket.Approved, "", nil, "other-instance")
	time.Sleep(300 * time.Millisecond)
	if e.gate.queue.Pending() != 1 {
		t.Fatalf("a replayed or forged decision ended the ask (pending %d)", e.gate.queue.Pending())
	}
	if r := e.post(c, `{"a":1}`); r.StatusCode == 200 {
		t.Fatal("a replayed or forged decision let the request through")
	}
}

// A denial within the hold answers the waiting request.
func TestHubDenied(t *testing.T) {
	e, fh := hubEnv(t, strings.Replace(testPolicy, `hold = "2s"`, `hold = "5s"`, 1), nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	go func() { fh.decide(fh.waitTickets(1)[0], ticket.Denied, "not now", nil, "") }()
	r := e.post(c, `{"a":2}`)
	if r.Header.Get("X-LockHTTP-Code") != "E_DENIED" {
		t.Fatalf("denied: %s %v", r.Status, r.Header)
	}
	if !hasRecord(e.auditText(), map[string]string{"event": "denied", "approval": "hub", "reason": "not now"}) {
		t.Errorf("audit lacks the hub denial:\n%s", e.auditText())
	}
}

// Asks wait for the hub side by side, not one behind the other.
func TestHubAsksConcurrent(t *testing.T) {
	e, fh := hubEnv(t, hubTestPolicy, nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	var wg sync.WaitGroup
	for i := range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); e.post(c, `{"n":`+strconv.Itoa(i)+`}`) }()
	}
	wg.Wait()
	if n := len(fh.waitTickets(3)); n != 3 {
		t.Fatalf("tickets %d, want 3 at once", n)
	}
}

// A CONNECT approved on the hub opens the host for the connect grant.
func TestHubConnectGrant(t *testing.T) {
	e, fh := hubEnv(t, hubTestPolicy, nil)
	e.gate.cfg.Certs = nil // decide at the domain
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", false)
	get := func() (*http.Response, error) { return c.Get("https://example.com/x") }
	if _, err := get(); err == nil {
		t.Fatal("unknown host opened without a decision")
	}
	tk := fh.waitTickets(1)[0]
	if tk.Risk != ticket.RiskWrite {
		t.Errorf("CONNECT risk %s, want write", tk.Risk)
	}
	fh.decide(tk, ticket.Approved, "", nil, "")
	e.waitIdle()
	resp, err := get()
	if err != nil {
		t.Fatalf("granted host refused: %v", err)
	}
	resp.Body.Close()
}

// The hub is never a target: not by its names, not by a name resolving
// into its network, even when internal_hosts allows private addresses.
func TestHubNetworkRefused(t *testing.T) {
	conf := hubTestPolicy + `
[[profiles.default.internal_hosts]]
host = "lockhub"
ports = [8443, 80]
read = true

[[profiles.default.internal_hosts]]
host = "private.test"
ports = [8443, 80]
read = true
`
	e, _ := hubEnv(t, conf, func(h *Hub) {
		h.Hosts = []string{"lockhub"}
		h.Nets = []netip.Prefix{netip.MustParsePrefix("10.1.2.0/24")} // private.test resolves to 10.1.2.3
	})
	for _, target := range []string{"http://lockhub:8443/v1/hello", "http://LOCKHUB.:80/", "http://private.test:8443/v1/hello"} {
		resp, err := e.client("dev-5", false).Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_FLOOR" {
			t.Errorf("%s: %s %v", target, resp.Status, resp.Header)
		}
	}
	if !strings.Contains(e.auditText(), `"rule":"floor:hub"`) {
		t.Errorf("audit lacks the hub refusal:\n%s", e.auditText())
	}
	// A CONNECT to the hub is refused before any tunnel.
	if _, err := e.client("dev-5", false).Get("https://lockhub:8443/v1/hello"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("CONNECT lockhub: %v", err)
	}
	// A name that does not resolve cannot be checked: refused.
	e.gate.cfg.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if d, stop := e.gate.hubTarget(context.Background(), "unknown.test"); !stop || d.Rule != "floor:hub" {
		t.Errorf("unresolvable name: %+v %v", d, stop)
	}
	e.gate.cfg.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "private.test" {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	// The dialer refuses an address of the hub's network too.
	if _, err := e.gate.dialTarget(context.Background(), "tcp", "private.test:80"); err == nil || !strings.Contains(err.Error(), "hub") {
		t.Errorf("dial into the hub's network: %v", err)
	}
}

func TestHubRisk(t *testing.T) {
	prod := &policy.Policy{Production: true}
	for _, c := range []struct {
		pol  *policy.Policy
		p    wire.ApproveParams
		want ticket.Risk
	}{
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "GET"}}, ticket.RiskWrite},
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "HEAD"}}, ticket.RiskWrite},
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "GET", ReqBytes: 3}}, ticket.RiskWrite},
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "POST"}}, ticket.RiskWrite},
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "GET", QueryLen: 12}}, ticket.RiskWrite},
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "GET", ReqHeaders: []string{"connection", "upgrade"}}}, ticket.RiskWrite},
		{&policy.Policy{}, wire.ApproveParams{Target: wire.Target{Phase: "connect", Method: "CONNECT"}}, ticket.RiskWrite},
		{prod, wire.ApproveParams{Target: wire.Target{Phase: "http", Method: "GET"}}, ticket.RiskProdWrite},
	} {
		if got := riskOf(c.pol, c.p); got != c.want {
			t.Errorf("%+v production=%v: %s, want %s", c.p.Target, c.pol.Production, got, c.want)
		}
	}
}

type testLog struct{ t *testing.T }

func (l testLog) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// hasRecord reports an audit line holding every field of want.
func hasRecord(audit string, want map[string]string) bool {
	for _, line := range strings.Split(audit, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		all := true
		for k, v := range want {
			all = all && m[k] == v
		}
		if all {
			return true
		}
	}
	return false
}

// A gate that stops withdraws the tickets it was waiting on.
func TestHubWithdrawOnStop(t *testing.T) {
	e, fh := hubEnv(t, hubTestPolicy, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.gate.hubApprove(ctx, "fp-withdraw", wire.ApproveParams{Source: wire.Source{Container: "local"},
			Target: wire.Target{Phase: "http", Method: "POST", Host: "example.com"}})
		done <- err
	}()
	tk := fh.waitTickets(1)[0]
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("stopped ask: %v", err)
	}
	if !fh.withdrawn(tk.ID) {
		t.Fatal("the ticket of a stopped ask was not withdrawn")
	}
}
