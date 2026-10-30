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

// hubApprove asks the hub about one held request and waits for its
// decision, until ctx ends. It answers like a console: nil when approved,
// a *Refusal for a denial, an expired ticket or a request that went stale.
func (g *Gate) hubApprove(ctx context.Context, fp string, p wire.ApproveParams) (wire.ApproveResult, error) {
	h := g.cfg.Hub
	pol, polFP := g.Policy()
	if pol == nil || polFP == "" {
		return wire.ApproveResult{}, ErrNoConsole
	}
	if err := wire.Bound(&p); err != nil {
		return wire.ApproveResult{}, &Refusal{Code: string(product.CodeFloor), Reason: err.Error()}
	}
	// A hub decision comes long after the agent stopped waiting: approving
	// lets the same request through once.
	p.ClientGone = true
	body, err := json.Marshal(hubPlan{Fingerprint: fp, Params: p})
	if err != nil {
		return wire.ApproveResult{}, err
	}
	risk := riskOf(pol, p)
	planHash := planHashOf(fp)
	caller := plans.Caller{UID: os.Getuid()}
	pl, err := h.Plans.Create(plans.Binding{UID: caller.UID, Agent: p.Agent, PolicyFP: polFP, PlanHash: planHash}, body, ticket.ClampTTL(risk, 0))
	if err != nil {
		return wire.ApproveResult{}, &Refusal{Code: string(product.CodePending), Reason: "the gate cannot hold more requests for the hub: " + err.Error()}
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
	// preview stays masked, as on the console): with --seal-clear it is
	// sealed to each pinned device, which the hub relays without reading;
	// otherwise it never leaves the gate.
	clearScreen := &ticket.Screen{Header: header, Body: rows, Warnings: p.Warnings, Red: p.Red}
	id, err := h.Client.SubmitClear(ctx, h.Plans, pl.ID, caller, t, screen, clearScreen)
	switch {
	case errors.Is(err, hubclient.ErrRateLimited):
		_ = h.Plans.End(pl.ID, caller, plans.Withdrawn, err.Error())
		return wire.ApproveResult{}, &Refusal{Code: string(product.CodePending), Reason: "too many requests wait for the hub: retry later"}
	case errors.Is(err, hubclient.ErrUnreachable):
		// The ticket is signed and kept: the client's watch sends it when
		// the hub answers again. Nothing falls back to another approver.
		fmt.Fprintln(g.cfg.Log, "lockhttp gate: hub unreachable, ticket", id, "kept pending")
	case err != nil:
		_ = h.Plans.End(pl.ID, caller, plans.Withdrawn, err.Error())
		return wire.ApproveResult{}, &Refusal{Code: string(product.CodeNoConsole), Reason: "the hub refused the ticket"}
	}
	recheck := func(pl *plans.Plan) (string, string, error) {
		var b hubPlan
		if err := json.Unmarshal(pl.Body, &b); err != nil {
			return "", "", err
		}
		_, fp := g.Policy()
		return fp, planHashOf(b.Fingerprint), nil
	}
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
	for {
		run, d, err := h.Client.Begin(h.Plans, id, caller, recheck)
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
			record(audit.EventTimeout, "the approval expired", d)
			return wire.ApproveResult{}, &Refusal{Code: string(product.CodeTimeout), Reason: "the approval expired"}
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
			if err := h.Client.Withdraw(wctx, h.Plans, pl.ID, caller, "the gate stopped"); err != nil {
				fmt.Fprintln(g.cfg.Log, "lockhttp gate: ticket", id, "not withdrawn:", err)
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
