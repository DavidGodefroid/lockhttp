package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhttp/internal/decide"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// Hub sends the gate's asks to lockhub instead of the console: each held
// request becomes a plan and a signed ticket, and a decision that verifies
// under the pinned hub key grants the same single-use pass (or connect
// grant) a console approval does. The console still serves the policy.
type Hub struct {
	Client *hubclient.Client
	Plans  *plans.Store
	// Hosts are the names of the hub on its network and Nets its
	// addresses: the gate refuses them as targets, whatever internal_hosts
	// allows, so that an agent never reaches the hub through the gate.
	Hosts []string
	Nets  []netip.Prefix
	// Poll is how often a held ask looks for its decision (1 s by
	// default); the decisions arrive by the client's long poll.
	Poll time.Duration

	mu sync.Mutex
	// current is the ticket each ask in flight waits on, by request
	// fingerprint (the E_PENDING answer names it); expired the tickets
	// that expired with nobody asking, renewed when the same request
	// comes again.
	current map[string]string
	expired map[string]expiredTicket
}

// Close closes the plan store (it holds its directory for this process):
// after the gate stopped (Gate.Stopped), never while asks wait.
func (h *Hub) Close() error { return h.Plans.Close() }

// hubPlan is the body of a plan: the request fingerprint (the plan hash is
// its hash) and what the screen showed.
type hubPlan struct {
	Fingerprint string             `json:"fingerprint"`
	Params      wire.ApproveParams `json:"params"`
}

// planHashOf is the plan hash of a request fingerprint.
func planHashOf(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// riskOf is the ticket's risk class: a write, or a prod-write under a
// production policy (which remote facades never answer). An ask is never
// a read: every part of a held request (path, headers, query, body, a
// CONNECT's tunnel) can carry data the agent chose, and the gate asks
// only about what its policy does not let through freely.
func riskOf(pol *policy.Policy, _ wire.ApproveParams) ticket.Risk {
	if pol != nil && pol.Production {
		return ticket.RiskProdWrite
	}
	return ticket.RiskWrite
}

// planInputs are the inputs of a plan hash (ticket.InputDigests): the
// request fingerprint, which the plan hash is the hash of, and the policy
// it was asked under. A renewal names those that moved
// (ticket.Renewal.Changes): a plan of the gate is the request itself, so
// only a policy change can move one, and lockkit refuses that renewal
// (plan again).
type planInputs struct {
	Request string `json:"request"`
	Policy  string `json:"policy"`
}

// bindingOf is what the gate binds a plan to, from the request
// fingerprint fp and the policy fingerprint polFP: the plan hash and its
// inputs. The plan, the run's recheck and a renewal's recompute all use
// it.
func bindingOf(fp, polFP string) (planHash string, inputs map[string]string, err error) {
	inputs, err = ticket.InputDigests(planInputs{Request: fp, Policy: polFP})
	return planHashOf(fp), inputs, err
}

// recompute is the gate's hubclient.Recompute: the policy fingerprint in
// force, the plan hash and its inputs of a stored plan, as the recheck
// before a run computes them. It runs nothing.
func (g *Gate) recompute(pl *plans.Plan) (policyFP, planHash string, inputs map[string]string, err error) {
	var b hubPlan
	if err := json.Unmarshal(pl.Body, &b); err != nil {
		return "", "", nil, err
	}
	_, polFP := g.Policy()
	if polFP == "" {
		return "", "", nil, ErrNoConsole
	}
	planHash, inputs, err = bindingOf(b.Fingerprint, polFP)
	return polFP, planHash, inputs, err
}

// recheck is the gate's hubclient.Recheck: recompute without the inputs.
func (g *Gate) recheck(pl *plans.Plan) (string, string, error) {
	fp, hash, _, err := g.recompute(pl)
	return fp, hash, err
}

// hubRequest audits a hub request the gate acted on or refused (a reveal
// of a ticket's clear screen, a renewal of an expired ticket): the
// hubclient.Client.OnRequest of the gate, as lockkit's console does.
func (g *Gate) hubRequest(q *ticket.HubRequest, renewal string, err error) {
	if q == nil {
		fmt.Fprintln(g.cfg.Log, "lockhttp gate: hub request refused:", err)
		g.audit(wire.Record{Base: audit.Base{Event: audit.EventHubRequest, Decision: "refused", Error: err.Error(), Approval: "hub"}})
		return
	}
	// The approver is the hub's word: audited as claimed by the hub.
	b := audit.Base{Ticket: q.Ticket, Approver: &ticket.Approver{ID: q.Approver.ID, Display: q.Approver.Display}, Facade: q.Facade, Approval: "hub-claimed"}
	switch q.Kind {
	case ticket.RequestReveal:
		b.Event, b.Decision = audit.EventReveal, "sealed"
	default:
		b.Event, b.Decision = audit.EventRenew, "renewed"
	}
	switch {
	case err != nil:
		b.Decision, b.Error = "refused", err.Error()
		fmt.Fprintf(g.cfg.Log, "lockhttp gate: ticket %s: %s by %s on %s refused: %v\n", q.Ticket, q.Kind, q.Approver.ID, q.Facade, err)
	case q.Kind == ticket.RequestReveal:
		fmt.Fprintf(g.cfg.Log, "lockhttp gate: ticket %s: clear screen sealed to %s on %s\n", q.Ticket, q.Approver.ID, q.Facade)
	default:
		g.cfg.Hub.forgetTicket(q.Ticket)
		b.Reason = "renewed by ticket " + renewal
		fmt.Fprintf(g.cfg.Log, "lockhttp gate: ticket %s: asked again by %s on %s as ticket %s\n", q.Ticket, q.Approver.ID, q.Facade, renewal)
	}
	g.audit(wire.Record{Base: b})
}

// expiredKeep is how long the gate remembers an expired ticket for a
// request sent again: a renewal asks again for it (plans.Retention).
const expiredKeep = plans.Retention

type expiredTicket struct {
	id string
	at time.Time
}

// ticketOf is the ticket an ask of fingerprint fp waits on, "" for none.
func (h *Hub) ticketOf(fp string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current[fp]
}

func (h *Hub) setTicket(fp, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.current == nil {
		h.current = map[string]string{}
	}
	if id == "" {
		delete(h.current, fp)
	} else {
		h.current[fp] = id
	}
}

// remember keeps the expired ticket id of fp, for a renewal when the same
// request comes again.
func (h *Hub) remember(fp, id string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.expired == nil {
		h.expired = map[string]expiredTicket{}
	}
	for k, x := range h.expired {
		if now.Sub(x.at) > expiredKeep {
			delete(h.expired, k)
		}
	}
	h.expired[fp] = expiredTicket{id: id, at: now}
}

// forgetTicket drops the expired ticket id, whatever request it was
// remembered for: the hub renewed it (the renewal is pending, found by
// its plan hash).
func (h *Hub) forgetTicket(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for fp, x := range h.expired {
		if x.id == id {
			delete(h.expired, fp)
		}
	}
}

// pendingTicket reports whether ticket id's plan waits for a decision.
func (h *Hub) pendingTicket(id string, caller plans.Caller) bool {
	pl, err := h.Plans.ByTicket(id, caller)
	return err == nil && pl.State == plans.Pending
}

// takeExpired returns, and forgets, the expired ticket of fp.
func (h *Hub) takeExpired(fp string, now time.Time) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	x, ok := h.expired[fp]
	delete(h.expired, fp)
	if !ok || now.Sub(x.at) > expiredKeep {
		return ""
	}
	return x.id
}

// hubSubmit gives the ticket the ask of fingerprint fp waits on: the
// pending ticket of the same plan (a gate restarted while it waited), the
// renewal of the ticket that expired for it (decision H1: the hub shows
// it as asked again, with what moved; renewed is the expired ticket), or
// a new plan and ticket. It answers like hubApprove when no ticket can be
// had.
func (g *Gate) hubSubmit(ctx context.Context, fp string, p wire.ApproveParams, pol *policy.Policy, polFP string, caller plans.Caller) (id, renewed string, err error) {
	h := g.cfg.Hub
	planHash, inputs, err := bindingOf(fp, polFP)
	if err != nil {
		return "", "", err
	}
	// Either way the expired ticket remembered for this request is spent:
	// a pending plan (a renewal the human made from the hub) supersedes it.
	old := h.takeExpired(fp, g.cfg.Now())
	if pl, ok := h.Plans.FindPending(caller, planHash); ok && pl.Ticket != "" {
		return pl.Ticket, "", nil
	}
	if old != "" {
		id, err := h.Client.Renew(ctx, h.Plans, old, caller)
		switch {
		case id != "" && h.pendingTicket(id, caller):
			if err != nil {
				fmt.Fprintln(g.cfg.Log, "lockhttp gate: renewal", id, "of ticket", old, "not sent yet:", err)
			}
			return id, old, nil
		case id != "":
			// A renewal that ran, was denied or ended otherwise: nothing to
			// wait on. A new plan.
			fmt.Fprintln(g.cfg.Log, "lockhttp gate: renewal", id, "of ticket", old, "is not pending: asking again")
		case errors.Is(err, hubclient.ErrRateLimited):
			return "", "", &Refusal{Code: string(product.CodePending), Reason: "too many requests wait for the hub: retry later"}
		default:
			// Not renewable (hubclient.ErrNotRenewable: the policy
			// changed, the plan is gone, its renewal ran or was denied):
			// a new plan, under the policy in force.
			fmt.Fprintln(g.cfg.Log, "lockhttp gate: ticket", old, "not renewed:", err)
		}
	}
	// A hub decision comes long after the agent stopped waiting: approving
	// lets the same request through once.
	p.ClientGone = true
	body, err := json.Marshal(hubPlan{Fingerprint: fp, Params: p})
	if err != nil {
		return "", "", err
	}
	risk := riskOf(pol, p)
	pl, err := h.Plans.Create(plans.Binding{UID: caller.UID, Agent: p.Agent, PolicyFP: polFP, PlanHash: planHash, Inputs: inputs}, body, ticket.ClampTTL(risk, 0))
	if err != nil {
		return "", "", &Refusal{Code: string(product.CodePending), Reason: "the gate cannot hold more requests for the hub: " + err.Error()}
	}
	t := ticket.NewTicket(ticket.Source{Lock: product.P.Name}, risk, planHash, polFP, g.cfg.Now(), ticket.ClampTTL(risk, 0))
	t.Requester = ticket.Requester{Agent: p.Agent, Session: p.Container}
	// The hub cannot check a verdict="auto" rule against the console's
	// policy, as the console does: no hub auto mode for the gate's asks.
	t.Flags = ticket.Flags{Production: pol.Production, NeverAuto: true}
	header, rows := wire.ScreenHeader(p), append([]string{"from " + wire.ScreenRequester(p)}, wire.ScreenBody(p)...)
	lines := make([]render.Line, 0, len(rows))
	for _, l := range rows {
		lines = append(lines, render.Structure(l))
	}
	screen := render.MaskScreen(render.ScreenSource{Header: header, Body: lines, Warnings: p.Warnings, Red: p.Red},
		render.Masking{Detectors: previewDetectors})
	// The screen the console would show, personal data unmasked (the body
	// preview stays masked, as on the console): kept in the gate's volume,
	// it leaves only sealed: to a pinned facade on a reveal (Ctrl-O), and
	// with --seal-clear to each pinned device. The hub relays ciphertext.
	clearScreen := &ticket.Screen{Header: header, Body: rows, Warnings: p.Warnings, Red: p.Red}
	id, err = h.Client.SubmitClear(ctx, h.Plans, pl.ID, caller, t, screen, clearScreen)
	switch {
	case errors.Is(err, hubclient.ErrRateLimited):
		_ = h.Plans.End(pl.ID, caller, plans.Withdrawn, err.Error())
		return "", "", &Refusal{Code: string(product.CodePending), Reason: "too many requests wait for the hub: retry later"}
	case errors.Is(err, hubclient.ErrUnreachable):
		// The ticket is signed and kept: the client's watch sends it when
		// the hub answers again. Nothing falls back to another approver.
		fmt.Fprintln(g.cfg.Log, "lockhttp gate: hub unreachable, ticket", id, "kept pending")
	case err != nil:
		_ = h.Plans.End(pl.ID, caller, plans.Withdrawn, err.Error())
		return "", "", &Refusal{Code: string(product.CodeNoConsole), Reason: "the hub refused the ticket"}
	}
	return id, "", nil
}

// ApprovalHubRun is the approval of the record of a request run after the
// hub approved it within the hold. The decision itself is the record
// hubApprove writes (approval "hub", with the ticket, the approver and
// the hub's signature): lockhub's `lox audit verify --lock` takes every
// approved or denied record with approval "hub" for a hub decision, so the
// run must not carry that value (it would read as an unsigned decision, or
// a second approval of the ticket).
const ApprovalHubRun = "hub-run"

// hubApprove asks the hub about one held request and waits for its
// decision, until ctx ends. It answers like a console: nil when approved,
// a *Refusal for a denial, an expired ticket or a request that went stale.
// A ticket that expires while the agent still sends the request is asked
// again (a renewal, decision H1); one nobody asks for any more ends the
// ask, and the same request sent later renews it.
func (g *Gate) hubApprove(ctx context.Context, fp string, p wire.ApproveParams) (wire.ApproveResult, error) {
	h := g.cfg.Hub
	pol, polFP := g.Policy()
	if pol == nil || polFP == "" {
		return wire.ApproveResult{}, ErrNoConsole
	}
	if err := wire.Bound(&p); err != nil {
		return wire.ApproveResult{}, &Refusal{Code: string(product.CodeFloor), Reason: err.Error()}
	}
	caller := plans.Caller{UID: os.Getuid()}
	id, renewed, err := g.hubSubmit(ctx, fp, p, pol, polFP, caller)
	if err != nil {
		return wire.ApproveResult{}, err
	}
	h.setTicket(fp, id)
	defer h.setTicket(fp, "")
	asks := g.queue.asks(fp)
	poll := h.Poll
	if poll <= 0 {
		poll = time.Second
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	// The decision is audited here, as the console audits its own, with
	// who answered, where, and the hub's signature: the request's later
	// record (grant:once) does not name the ticket.
	record := func(event, reason string, d *ticket.Decision) {
		b := audit.Base{Event: event, Decision: event, Approval: "hub", Reason: reason, Warnings: p.Warnings, Ticket: id}
		if d != nil {
			b.Approver, b.Facade, b.HubSig = &d.Approver, d.Facade, d.Sig
		}
		g.audit(wire.Record{Base: b, RequestID: p.RequestID, Source: p.Source, Target: p.Target, Rule: p.Rule, Class: p.Class,
			Score: p.Score, PolicyFP: polFP})
	}
	if renewed != "" {
		record(audit.EventRenew, "ticket "+renewed+" expired: asked again as ticket "+id, nil)
	}
	for {
		run, d, err := h.Client.Begin(h.Plans, id, caller, g.recheck)
		switch {
		case err == nil:
			record(audit.EventApproved, "", d)
			// The pass the caller grants is the plan's one run.
			if err := h.Client.Finish(ctx, h.Plans, run.ID, caller, true, "single-use pass granted"); err != nil {
				fmt.Fprintln(g.cfg.Log, "lockhttp gate: hub not told ticket", id, "was consumed:", err)
			}
			return wire.ApproveResult{Approved: true}, nil
		case errors.Is(err, ticket.ErrDevice) && d != nil:
			// An approval this gate wants signed by a pinned device
			// (--require-device) came without one: the plan ended Denied.
			// The audit names the facade it came from.
			reason := "the approval was not signed by a pinned device"
			record(audit.EventDenied, reason, d)
			return wire.ApproveResult{}, &Refusal{Code: string(product.CodeDenied), Reason: reason}
		case errors.Is(err, hubclient.ErrPending):
		case errors.Is(err, hubclient.ErrBadDecision):
			// A decision that does not verify was dropped (a forged one,
			// or one of the mobile facade without the signature of a
			// pinned device): wait for one that does.
			fmt.Fprintln(g.cfg.Log, "lockhttp gate: ticket", id, "decision dropped:", err)
		case errors.Is(err, hubclient.ErrDenied):
			reason := strings.TrimPrefix(strings.TrimPrefix(err.Error(), hubclient.ErrDenied.Error()), ": ")
			if reason == "" {
				reason = "denied on the hub"
			}
			record(audit.EventDenied, reason, d)
			return wire.ApproveResult{}, &Refusal{Code: string(product.CodeDenied), Reason: reason}
		case errors.Is(err, ticket.ErrExpired):
			if n := g.queue.asks(fp); n > asks {
				// The agent sent the request again while this ticket
				// waited: ask again (Renew), and its retries see the new
				// ticket pending.
				nid, rerr := h.Client.Renew(ctx, h.Plans, id, caller)
				if nid != "" && h.pendingTicket(nid, caller) {
					if rerr != nil {
						fmt.Fprintln(g.cfg.Log, "lockhttp gate: renewal", nid, "of ticket", id, "not sent yet:", rerr)
					}
					old := id
					id, asks = nid, n
					record(audit.EventRenew, "ticket "+old+" expired: asked again as ticket "+id, d)
					h.setTicket(fp, id)
					break
				}
				fmt.Fprintln(g.cfg.Log, "lockhttp gate: ticket", id, "not renewed:", rerr)
			} else {
				h.remember(fp, id, g.cfg.Now())
			}
			record(audit.EventTimeout, "the approval expired", d)
			return wire.ApproveResult{}, &Refusal{Code: string(product.CodeTimeout), Ticket: id,
				Reason: "ticket " + id + " expired before it was used"}
		case errors.Is(err, plans.ErrStale):
			return wire.ApproveResult{}, &Refusal{Code: string(product.CodeDenied), Reason: "the policy changed while the request waited: send it again"}
		default:
			return wire.ApproveResult{}, &Refusal{Code: string(product.CodeDenied), Reason: "the hub's decision cannot be used: " + err.Error()}
		}
		select {
		case <-ctx.Done():
			// The gate stops: no one holds this request any more, so its
			// ticket is withdrawn rather than left for a decision nothing
			// will act on (a retry asks again).
			wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if pl, err := h.Plans.ByTicket(id, caller); err == nil {
				if err := h.Client.Withdraw(wctx, h.Plans, pl.ID, caller, "the gate stopped"); err != nil {
					fmt.Fprintln(g.cfg.Log, "lockhttp gate: ticket", id, "not withdrawn:", err)
				}
			}
			cancel()
			return wire.ApproveResult{}, ctx.Err()
		case <-tick.C:
		}
	}
}

// hubTarget refuses a target that is the hub: one of its names, or a name
// that resolves into its networks. internal_hosts cannot open it.
func (g *Gate) hubTarget(ctx context.Context, host string) (decide.Decision, bool) {
	h := g.cfg.Hub
	if h == nil {
		return decide.Decision{}, false
	}
	refused := decide.Decision{Verdict: decide.Deny, Rule: "floor:hub", Code: product.CodeFloor, Reason: host + " is the approval hub: agents never reach it"}
	for _, n := range h.Hosts {
		if strings.EqualFold(strings.TrimSuffix(host, "."), n) {
			return refused, true
		}
	}
	if len(h.Nets) == 0 {
		return decide.Decision{}, false
	}
	ips, err := g.resolve(ctx, host)
	if err != nil {
		// Fail closed: a name the gate cannot check against the hub's
		// networks is not let through to a resolver that might answer.
		refused.Reason = host + " does not resolve here, so it cannot be checked against the hub's network"
		return refused, true
	}
	if g.onHubNet(ips) {
		return refused, true
	}
	return decide.Decision{}, false
}

// onHubNet reports an address in the hub's networks.
func (g *Gate) onHubNet(ips []netip.Addr) bool {
	if g.cfg.Hub == nil {
		return false
	}
	for _, ip := range ips {
		for _, n := range g.cfg.Hub.Nets {
			if n.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}

func (g *Gate) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.cfg.Resolve != nil {
		return g.cfg.Resolve(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
