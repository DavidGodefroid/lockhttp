package gate

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

func newPhone(name string) *devicetest.Authenticator {
	return devicetest.New("hub.example.net", "https://hub.example.net", name)
}

// pinned pins devs, with the risks that need one and seal-clear.
func pinned(seal bool, require []ticket.Risk, devs ...*devicetest.Authenticator) func(*hubclient.Config) {
	return func(c *hubclient.Config) {
		for _, d := range devs {
			c.Devices = append(c.Devices, d.Device())
		}
		c.RequireDevice, c.SealClear = require, seal
	}
}

// raw is the ticket id as the gate signed and pushed it.
func (h *fakeHub) rawTicket(id string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.raw[id]
}

// A decision taken on a pinned device runs the request once. With
// --seal-clear the clear screen reaches the hub only sealed to the device.
func TestHubDeviceDecisionRunsOnce(t *testing.T) {
	phone := newPhone("phone")
	e, fh := hubEnvWith(t, hubTestPolicy, pinned(true, []ticket.Risk{ticket.RiskWrite}, phone), nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	if r := e.post(c, `{"to":"jean.dupont@example.org"}`); r.Header.Get("X-LockHTTP-Code") != "E_PENDING" {
		t.Fatalf("hold: %s %v", r.Status, r.Header)
	}
	tk := fh.waitTickets(1)[0]
	raw := fh.rawTicket(tk.ID)
	if strings.Contains(string(raw), "jean.dupont@example.org") {
		t.Fatalf("the hub saw the clear screen: %s", raw)
	}
	if len(tk.PII.SealedFor) != 1 || tk.PII.SealedFor[0].Device != phone.Device().ID {
		t.Fatalf("sealed_for: %+v", tk.PII.SealedFor)
	}
	clear, err := ticket.OpenClearScreen(phone.Seal, tk.ID, phone.Device().ID, &tk.PII.SealedFor[0])
	if err != nil || !strings.Contains(clear.Header, "POST example.com") || !slices.ContainsFunc(clear.Body, func(l string) bool { return strings.Contains(l, "from ") }) {
		t.Fatalf("clear screen %+v %v", clear, err)
	}
	fh.decideWith(tk, ticket.Approved, "", nil, "", func(d *ticket.Decision) { phone.Decide(d, raw) })
	e.waitIdle()
	if r := e.post(c, `{"to":"jean.dupont@example.org"}`); r.StatusCode != 200 {
		t.Fatalf("device-approved request refused: %s %v", r.Status, r.Header)
	}
	if r := e.post(c, `{"to":"jean.dupont@example.org"}`); r.Header.Get("X-LockHTTP-Code") != "E_PENDING" {
		t.Fatalf("the pass was used twice: %s %v", r.Status, r.Header)
	}
	if !hasRecord(e.auditText(), map[string]string{"event": "approved", "approval": "hub", "ticket": tk.ID, "facade": ticket.FacadeMobile}) {
		t.Errorf("audit lacks the device approval:\n%s", e.auditText())
	}
}

// Without a pinned device, a decision of the mobile facade is refused
// (fails closed), and so is one signed by a device this gate does not pin.
// Without --seal-clear no clear screen leaves the gate.
func TestHubMobileWithoutPinnedDeviceRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		pin  []*devicetest.Authenticator
	}{{"no device pinned", nil}, {"another device pinned", []*devicetest.Authenticator{newPhone("tablet")}}} {
		t.Run(c.name, func(t *testing.T) {
			phone := newPhone("phone")
			e, fh := hubEnvWith(t, hubTestPolicy, pinned(false, nil, c.pin...), nil)
			e.backend("example.com", true, http.HandlerFunc(ok))
			e.remap("example.com", "443")
			cl := e.client("dev-5", true)
			e.post(cl, `{"a":1}`)
			tk := fh.waitTickets(1)[0]
			if tk.PII.SealedFor != nil {
				t.Fatalf("a clear screen left without --seal-clear: %+v", tk.PII.SealedFor)
			}
			raw := fh.rawTicket(tk.ID)
			// The hub says the phone approved, without its signature, then
			// with the signature of a phone this gate does not pin.
			fh.decideWith(tk, ticket.Approved, "", nil, "", func(d *ticket.Decision) { d.Facade = ticket.FacadeMobile })
			fh.decideWith(tk, ticket.Approved, "", nil, "", func(d *ticket.Decision) { phone.Decide(d, raw) })
			time.Sleep(300 * time.Millisecond)
			if e.gate.queue.Pending() != 1 {
				t.Fatalf("an unverified mobile decision ended the ask (pending %d)", e.gate.queue.Pending())
			}
			if r := e.post(cl, `{"a":1}`); r.StatusCode == 200 {
				t.Fatal("an unverified mobile decision let the request through")
			}
		})
	}
}

// With --require-device, an approval of that risk on the terminal (tty)
// is refused: the hub's word alone is not enough.
func TestHubRequireDeviceRefusesTTY(t *testing.T) {
	phone := newPhone("phone")
	e, fh := hubEnvWith(t, strings.Replace(testPolicy, `hold = "2s"`, `hold = "5s"`, 1), pinned(false, []ticket.Risk{ticket.RiskWrite}, phone), nil)
	e.backend("example.com", true, http.HandlerFunc(ok))
	e.remap("example.com", "443")
	c := e.client("dev-5", true)
	go func() { fh.decide(fh.waitTickets(1)[0], ticket.Approved, "", nil, "") }()
	r := e.post(c, `{"a":2}`)
	if r.StatusCode == 200 || r.Header.Get("X-LockHTTP-Code") != "E_DENIED" {
		t.Fatalf("tty approval with --require-device: %s %v", r.Status, r.Header)
	}
	if !hasRecord(e.auditText(), map[string]string{"event": "denied", "approval": "hub", "facade": "tty"}) {
		t.Errorf("audit lacks the refused approval:\n%s", e.auditText())
	}
	if r := e.post(c, `{"a":2}`); r.StatusCode == 200 {
		t.Fatal("the refused approval let a retry through")
	}
}
