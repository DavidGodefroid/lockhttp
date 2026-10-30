//go:build unix

// The gate's plans are bound to a Unix uid (a hub request for a plan of
// uid -1, as os.Getuid gives on Windows, is refused).

package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// clock is a test clock shared by the gate, its plans and its hub client.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// lockhubEnv is a gate in hub mode against lockkit's fake hub (hubtest),
// with an injected clock. dir is the gate's hub state directory.
type lockhubEnv struct {
	*env
	hub     *hubtest.Hub
	clock   *clock
	h       *Hub
	lockPub ed25519.PublicKey
	dir     string
}

func newLockhubEnv(t *testing.T, mod func(*hubclient.Config)) *lockhubEnv {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, "egress", pub)
	// hubtest answers the decisions poll at once: slow it down, as a long
	// poll would, so that the client's watch does not spin.
	target, _ := url.Parse(hub.URL())
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorLog = log.New(io.Discard, "", 0) // the polls cancelled at the end
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/decisions" {
			time.Sleep(20 * time.Millisecond)
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(slow.Close)
	c := &clock{t: time.Now().UTC().Truncate(time.Millisecond)}
	dir := t.TempDir()
	st, err := plans.Open(filepath.Join(dir, "plans"), plans.WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	cfg := hubclient.Config{URL: slow.URL, Instance: "egress", Key: key, HubKey: hub.Pub, Now: c.now,
		StateFile: filepath.Join(dir, "state.json")}
	if mod != nil {
		mod(&cfg)
	}
	cl, err := hubclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{Client: cl, Plans: st, Poll: 20 * time.Millisecond}
	var g *Gate
	t.Cleanup(func() {
		select {
		case <-g.Stopped():
		case <-time.After(10 * time.Second):
			t.Error("the gate did not stop")
		}
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	e := newEnv(t, hubTestPolicy, true, func(cfg *Config) { cfg.Hub = h; cfg.Log = testLog{t}; cfg.Now = c.now })
	g = e.gate
	e.console.answer = func(p wire.ApproveParams) (wire.ApproveResult, error) {
		t.Errorf("the console was asked about %s %s", p.Method, p.Host)
		return wire.ApproveResult{}, &Refusal{Code: "E_DENIED"}
	}
	return &lockhubEnv{env: e, hub: hub, clock: c, h: h, lockPub: pub, dir: dir}
}

// send posts body to url through the gate.
func (e *lockhubEnv) send(c *http.Client, u, body string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// pending checks an E_PENDING answer and returns the ticket it names.
func pending(t *testing.T, r *http.Response) string {
	t.Helper()
	if r.Header.Get("X-LockHTTP-Code") != "E_PENDING" {
		t.Fatalf("want E_PENDING: %s %v", r.Status, r.Header)
	}
	tk := r.Header.Get("X-LockHTTP-Ticket")
	if !ticket.ValidID(tk) {
		t.Fatalf("E_PENDING names no ticket: %v", r.Header)
	}
	return tk
}

func (e *lockhubEnv) signed(id string) *ticket.Ticket {
	e.t.Helper()
	tk, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(id))
	if err != nil {
		e.t.Fatalf("ticket %s: %v", id, err)
	}
	return tk
}

// The recompute of a renewal is the run's recheck: same policy, same plan
// hash, and the inputs the plan was bound to; a moved input shows by name.
func TestHubRecomputeIsRecheck(t *testing.T) {
	e := newLockhubEnv(t, nil)
	_, polFP := e.gate.Policy()
	fp := RequestFingerprint("dev-5", "POST", "https://example.com/up", http.Header{"Content-Type": {"application/json"}}, "sha256:x")
	body, _ := json.Marshal(hubPlan{Fingerprint: fp})
	hash, inputs, err := bindingOf(fp, polFP)
	if err != nil {
		t.Fatal(err)
	}
	pl := &plans.Plan{Body: body, Binding: plans.Binding{PolicyFP: polFP, PlanHash: hash, Inputs: inputs}}
	rfp, rhash, rinputs, err := e.gate.recompute(pl)
	if err != nil {
		t.Fatal(err)
	}
	cfp, chash, err := e.gate.recheck(pl)
	if err != nil {
		t.Fatal(err)
	}
	if rfp != polFP || cfp != polFP || rhash != chash || rhash != planHashOf(fp) {
		t.Fatalf("recompute %s %s, recheck %s %s, want %s %s", rfp, rhash, cfp, chash, polFP, planHashOf(fp))
	}
	if ch := ticket.DiffInputs(inputs, rinputs); len(ch) != 0 {
		t.Fatalf("the same plan moved: %v", ch)
	}
	// Through recompute, each input shows by name when it moves: a body
	// that no longer matches the plan's binding (another request) ...
	other := RequestFingerprint("dev-5", "POST", "https://example.com/up", http.Header{"Content-Type": {"application/json"}}, "sha256:y")
	otherBody, _ := json.Marshal(hubPlan{Fingerprint: other})
	_, ohash, moved, err := e.gate.recompute(&plans.Plan{Body: otherBody, Binding: pl.Binding})
	if ch := ticket.DiffInputs(inputs, moved); err != nil || ohash == hash || len(ch) != 1 || ch[0].Input != "request" {
		t.Fatalf("another request: changes %v (%v), want request", ch, err)
	}
	// ... and a new policy (which lockkit refuses to renew under).
	pol, _ := e.gate.Policy()
	e.gate.SetPolicy(pol, "sha256:"+strings.Repeat("0", 64))
	newFP, _, moved, err := e.gate.recompute(pl)
	if ch := ticket.DiffInputs(inputs, moved); err != nil || newFP == polFP || len(ch) != 1 || ch[0].Input != "policy" {
		t.Fatalf("another policy: changes %v (%v), want policy", ch, err)
	}
	e.gate.SetPolicy(pol, polFP)
	if _, _, _, err := e.gate.recompute(&plans.Plan{Body: []byte("not json")}); err == nil {
		t.Fatal("a broken plan recomputed")
	}
}

// H1: a ticket that expires undecided ends the ask; the same request sent
// again is asked again as a new ticket renewing the old one, pending with
// the new ticket; approved, the request runs once.
func TestHubExpiredTicketRenewed(t *testing.T) {
	e := newLockhubEnv(t, nil)
	var hits atomic.Int32
	e.backend("example.com", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); ok(w, r) }))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	const u, body = "https://example.com/up", `{"a":1}`
	first := pending(t, e.send(c, u, body))
	if e.signed(first).Renews != nil {
		t.Fatal("a first ticket renews something")
	}
	pl, err := e.h.Plans.ByTicket(first, plans.Caller{UID: os.Getuid()})
	if err != nil || pl.Binding.Inputs["request"] == "" || pl.Binding.Inputs["policy"] == "" {
		t.Fatalf("plan inputs: %+v %v", pl, err)
	}
	e.clock.add(25 * time.Hour) // past the write TTL, undecided
	e.waitIdle()
	second := pending(t, e.send(c, u, body))
	if second == first {
		t.Fatal("the expired ticket was offered again")
	}
	tk := e.signed(second)
	if tk.Renews == nil || tk.Renews.Of != first || tk.Renews.Reason != ticket.RenewExpired || !tk.Renews.Checked {
		t.Fatalf("renewal: %+v", tk.Renews)
	}
	// The gate's plan is the request: a request with another input is
	// another plan, so a renewal of the same request never shows a moved
	// input (and one under another policy is refused by lockkit).
	if len(tk.Renews.Changes) != 0 {
		t.Fatalf("changes %v", tk.Renews.Changes)
	}
	// The hub decides on the gate's clock (an approval is usable for its
	// TTL from its time).
	e.hub.DecideWith(second, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = e.clock.now() })
	e.waitIdle()
	if r := e.send(c, u, body); r.StatusCode != 200 {
		t.Fatalf("approved renewal refused: %s %v", r.Status, r.Header)
	}
	third := pending(t, e.send(c, u, body))
	if third == second || hits.Load() != 1 {
		t.Fatalf("the renewal ran %d times (next ticket %s)", hits.Load(), third)
	}
	if !e.hub.Consumed(second) {
		t.Error("the hub was not told the renewal was consumed")
	}
	audit := e.auditText()
	for _, want := range []map[string]string{
		{"event": "timeout", "ticket": first},
		{"event": "renew", "ticket": second, "reason": "ticket " + first + " expired: asked again as ticket " + second},
		{"event": "approved", "ticket": second},
		{"event": "refused", "code": "E_PENDING", "ticket": second},
	} {
		if !hasRecord(audit, want) {
			t.Errorf("audit lacks %v:\n%s", want, audit)
		}
	}
}

// A ticket that expires while the agent keeps sending the request is
// renewed in place: the retry is answered pending with the new ticket.
func TestHubExpiredWhileAskedRenewed(t *testing.T) {
	e := newLockhubEnv(t, nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	const u, body = "https://example.com/up", `{"a":2}`
	first := pending(t, e.send(c, u, body))
	if again := pending(t, e.send(c, u, body)); again != first {
		t.Fatalf("a retry got ticket %s, want %s", again, first)
	}
	done := make(chan string, 1)
	go func() { done <- pending(t, e.send(c, u, body)) }()
	time.Sleep(200 * time.Millisecond) // the retry joined the ask
	e.clock.add(25 * time.Hour)
	second := <-done
	if second == first {
		t.Fatal("the retry was not renewed")
	}
	if tk := e.signed(second); tk.Renews == nil || tk.Renews.Of != first {
		t.Fatalf("renewal: %+v", tk.Renews)
	}
	if e.gate.queue.Pending() != 1 {
		t.Fatalf("pending %d, want the renewed ask", e.gate.queue.Pending())
	}
}

// A renewal asked from the hub (the human, on a facade) and a reveal of
// the clear screen to a pinned facade (Ctrl-O) are answered and audited;
// the hub sees the masked screen only.
func TestHubRevealAndRenewRequests(t *testing.T) {
	fpub, fkey, _ := ed25519.GenerateKey(rand.Reader)
	e := newLockhubEnv(t, func(c *hubclient.Config) {
		c.Facades = []ticket.PinnedFacade{{Facade: ticket.FacadeTTY, Key: fpub}}
	})
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	id := pending(t, e.send(c, "https://example.com/users/jean.dupont@example.org", `{}`))
	tk := e.signed(id)
	if strings.Contains(string(e.hub.Ticket(id)), "jean.dupont") {
		t.Fatal("the hub saw the address")
	}
	rk, priv, err := ticket.NewRevealKey(fkey, ticket.FacadeTTY, tk, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	q := e.hub.Request(id, ticket.RequestReveal, rk, nil)
	ans := waitAnswer(t, e.hub, q)
	if strings.Contains(string(ans), "jean.dupont") {
		t.Fatal("the hub saw the clear screen")
	}
	var a struct {
		Reveal json.RawMessage `json:"reveal"`
	}
	if err := json.Unmarshal(ans, &a); err != nil || a.Reveal == nil {
		t.Fatalf("reveal answer %s", ans)
	}
	s, err := ticket.OpenReveal(e.lockPub, priv, rk, a.Reveal)
	if err != nil || !strings.Contains(strings.Join(s.Body, "\n"), "POST mitm://example.com/users/jean.dupont@example.org") {
		t.Fatalf("clear screen %+v %v", s, err)
	}
	// The ticket expires undecided; the human asks again from the hub.
	e.clock.add(25 * time.Hour)
	e.waitIdle()
	q = e.hub.Request(id, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = e.clock.now() })
	ans = waitAnswer(t, e.hub, q)
	var r struct{ Ticket string }
	if err := json.Unmarshal(ans, &r); err != nil || !ticket.ValidID(r.Ticket) {
		t.Fatalf("renew answer %s", ans)
	}
	if n := e.signed(r.Ticket); n.Renews == nil || n.Renews.Of != id || !n.Renews.Checked {
		t.Fatalf("renewal %+v", n.Renews)
	}
	// The agent's retry waits on the renewal the human made.
	if got := pending(t, e.send(c, "https://example.com/users/jean.dupont@example.org", `{}`)); got != r.Ticket {
		t.Fatalf("retry on %s, want the renewal %s", got, r.Ticket)
	}
	audit := e.auditText()
	if !hasRecord(audit, map[string]string{"event": "reveal", "decision": "sealed", "ticket": id, "facade": "tty", "approval": "hub-claimed"}) ||
		!hasRecord(audit, map[string]string{"event": "renew", "decision": "renewed", "ticket": id, "reason": "renewed by ticket " + r.Ticket}) {
		t.Errorf("audit lacks the hub requests:\n%s", audit)
	}
}

// A renewal made on the hub supersedes the expired ticket the gate kept
// for the request: once it ran (or expired in turn), the same request sent
// again is a new ticket, never a refusal about a spent one.
func TestHubRenewedOnHubThenSentAgain(t *testing.T) {
	e := newLockhubEnv(t, nil)
	var hits atomic.Int32
	e.backend("example.com", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); ok(w, r) }))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	const u, body = "https://example.com/up", `{"a":4}`
	at := func(q *ticket.HubRequest) { q.At = e.clock.now() }
	renewOnHub := func(id string) string {
		t.Helper()
		var r struct{ Ticket string }
		if err := json.Unmarshal(waitAnswer(t, e.hub, e.hub.Request(id, ticket.RequestRenew, nil, at)), &r); err != nil || !ticket.ValidID(r.Ticket) {
			t.Fatalf("renewal of %s: %v", id, err)
		}
		return r.Ticket
	}
	// T1 expires with nobody asking; the human renews it on the hub as T2.
	t1 := pending(t, e.send(c, u, body))
	e.clock.add(25 * time.Hour)
	e.waitIdle()
	t2 := renewOnHub(t1)
	if got := pending(t, e.send(c, u, body)); got != t2 {
		t.Fatalf("retry on %s, want the hub's renewal %s", got, t2)
	}
	e.h.mu.Lock()
	kept := len(e.h.expired)
	e.h.mu.Unlock()
	if kept != 0 {
		t.Fatalf("the gate still keeps %d expired ticket(s) the hub renewed", kept)
	}
	e.hub.DecideWith(t2, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = e.clock.now() })
	e.waitIdle()
	if r := e.send(c, u, body); r.StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("approved renewal: %s %v (ran %d)", r.Status, r.Header, hits.Load())
	}
	// Sent again: a new ticket, renewing nothing.
	t3 := pending(t, e.send(c, u, body))
	if t3 == t1 || t3 == t2 || e.signed(t3).Renews != nil {
		t.Fatalf("sent again: ticket %s renews %+v", t3, e.signed(t3).Renews)
	}
	// Variant: T3 expires, the hub renews it as T4, which expires too: the
	// request sent again is pending (a new ticket), not E_TIMEOUT.
	e.clock.add(25 * time.Hour)
	e.waitIdle()
	t4 := renewOnHub(t3)
	e.clock.add(25 * time.Hour)
	t5 := pending(t, e.send(c, u, body))
	if t5 == t3 || t5 == t4 || hits.Load() != 1 {
		t.Fatalf("after an expired hub renewal: ticket %s, ran %d", t5, hits.Load())
	}
}

func waitAnswer(t *testing.T, h *hubtest.Hub, q string) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := h.Answer(q); a != nil {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hub request %s not answered", q)
	return nil
}

// D.5: a gate started without its hub withdraws the plans its hub mode
// left pending, refuses their request explicitly, without asking the
// console or running it, and the next start in hub mode tells the hub.
func TestHubWithdrawnStandalone(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	hub := hubtest.New(t, "egress", pub)
	home := t.TempDir()
	dir := filepath.Join(home, "hub", "egress")
	newClient := func() *hubclient.Client {
		cl, err := hubclient.New(hubclient.Config{URL: hub.URL(), Instance: "egress", Key: key, HubKey: hub.Pub, StateFile: filepath.Join(dir, "state.json")})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	// The request as the gate fingerprints it, from a gate in hub mode.
	he := newLockhubEnv(t, nil)
	he.backend("example.com", true, http.HandlerFunc(ok))
	he.remap("example.com", "443")
	held, err := he.h.Plans.ByTicket(pending(t, he.send(he.client("dev-5", true), "https://example.com/up", `{"a":3}`)), plans.Caller{UID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	var b0 hubPlan
	if err := json.Unmarshal(held.Body, &b0); err != nil {
		t.Fatal(err)
	}
	fp, p := b0.Fingerprint, b0.Params
	_, polFP := he.gate.Policy()
	// Hub mode in the gate's volume: the request is a pending ticket; the
	// gate dies before it is decided (nothing withdraws it).
	st, err := plans.Open(filepath.Join(dir, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	hg := New(Config{Hub: &Hub{Client: newClient(), Plans: st}})
	id, _, err := hg.hubSubmit(context.Background(), fp, p, &policy.Policy{}, polFP, plans.Caller{UID: os.Getuid()})
	if err != nil || hub.Ticket(id) == nil {
		t.Fatalf("hub mode ticket %q: %v", id, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Standalone start.
	w, err := WithdrawStandalone(filepath.Join(home, "hub"))
	if err != nil || len(w.Tickets()) != 1 || w.Tickets()[0] != id {
		t.Fatalf("withdrawn %v: %v", w.Tickets(), err)
	}
	var hits atomic.Int32
	e := newEnv(t, testPolicy, true, func(cfg *Config) { cfg.Withdrawn = w })
	e.backend("example.com", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); ok(w, r) }))
	e.remap("example.com", "443")
	var asked atomic.Int32
	e.console.answer = func(wire.ApproveParams) (wire.ApproveResult, error) {
		asked.Add(1)
		return wire.ApproveResult{Approved: true}, nil
	}
	c := e.client("dev-5", true)
	req, _ := http.NewRequest("POST", "https://example.com/up", strings.NewReader(`{"a":3}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	_, _ = io.Copy(&b, resp.Body)
	if resp.StatusCode != 403 || resp.Header.Get("X-LockHTTP-Code") != "E_WITHDRAWN" || !strings.Contains(b.String(), "withdrawn: the gate runs without its hub") ||
		!strings.Contains(b.String(), id) {
		t.Fatalf("withdrawn ticket's request: %s %v\n%s", resp.Status, resp.Header, b.String())
	}
	if hits.Load() != 0 || asked.Load() != 0 {
		t.Fatalf("the withdrawn request ran %d times, the console was asked %d times", hits.Load(), asked.Load())
	}
	if !hasRecord(e.auditText(), map[string]string{"event": "refused", "code": "E_WITHDRAWN", "rule": "hub:withdrawn"}) {
		t.Errorf("audit lacks the refusal:\n%s", e.auditText())
	}
	// Sent again, it is a new request for the console.
	req, _ = http.NewRequest("POST", "https://example.com/up", strings.NewReader(`{"a":3}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := c.Do(req); err != nil || resp.StatusCode != 200 || asked.Load() != 1 {
		t.Fatalf("sent again: %v %v, console asked %d", resp, err, asked.Load())
	}
	// The next start in hub mode tells the hub.
	st, err = plans.Open(filepath.Join(dir, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := newClient().Sync(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if reason, ok := hub.Withdrawn(id); !ok || reason != StandaloneReason {
		t.Fatalf("hub withdrawal %q %v", reason, ok)
	}
}

// In hub mode an E_TIMEOUT names its expired ticket, and its hint says
// what renews it; the console's keeps "do not retry".
func TestHubTimeoutHint(t *testing.T) {
	var hub, console strings.Builder
	writeRefusalTicket(&hub, "r1", "E_TIMEOUT", "ticket T expired before it was used", "01M66R207TNWTJZASPXWVT2225", false)
	writeRefusal(&console, "r2", "E_TIMEOUT", "nobody answered", false)
	if h := hub.String(); !strings.Contains(h, "X-LockHTTP-Ticket: 01M66R207TNWTJZASPXWVT2225") || !strings.Contains(h, "send the same request again") || strings.Contains(h, "Do not retry") {
		t.Errorf("hub E_TIMEOUT:\n%s", h)
	}
	if !strings.Contains(console.String(), "Do not retry") {
		t.Errorf("console E_TIMEOUT:\n%s", console.String())
	}
}
