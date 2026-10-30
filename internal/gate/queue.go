package gate

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// Outcome is the answer to an ask.
type Outcome struct {
	Approved bool
	Auto     bool
	Code     string
	Reason   string
	// Ticket is the hub ticket an E_PENDING ask waits on (hub mode).
	Ticket string
}

// item is one held request; requests of identical fingerprint share it.
type item struct {
	fp, key string
	params  wire.ApproveParams
	// onApprove runs once when approved (a connect grant, a single-use
	// authorisation when the client left).
	onApprove func(clientGone bool)
	waiters   map[chan Outcome]bool
	sent      bool
	// asked counts the requests that waited on the item (the first and
	// every retry that joined it).
	asked int
}

// Queue holds the asks and sends them to the console one at a time
// (lockkit's console is serial, decision D7). A human decision is shared
// only by requests of identical fingerprint; requests under the same key
// with another fingerprint are separate items.
type Queue struct {
	console Console
	// approve, when set, answers an item instead of the console (hub
	// mode), and concurrent sends the items without waiting for the
	// previous answer.
	approve    func(ctx context.Context, fp string, p wire.ApproveParams) (wire.ApproveResult, error)
	concurrent bool
	// answering counts the answers in flight; stopped closes once Run
	// returned and they ended.
	answering sync.WaitGroup
	stopped   chan struct{}

	mu      sync.Mutex
	pending map[string]*item // by fingerprint
	order   []*item
	byKey   map[string]int
	wake    chan struct{}
	// onChange is told the pending counts (status file).
	onChange func(total int, byContainer map[string]int)
}

// NewQueue returns a queue sending to c.
func NewQueue(c Console) *Queue {
	return &Queue{console: c, pending: map[string]*item{}, byKey: map[string]int{}, wake: make(chan struct{}, 1), stopped: make(chan struct{})}
}

// Submit adds a waiter for the request of fingerprint fp. It returns the
// channel the outcome arrives on and a cancel func the waiter calls when
// it stops waiting (the item stays queued).
func (q *Queue) Submit(fp, key string, p wire.ApproveParams, onApprove func(clientGone bool)) (<-chan Outcome, func()) {
	ch := make(chan Outcome, 1)
	q.mu.Lock()
	it := q.pending[fp]
	if it == nil {
		it = &item{fp: fp, key: key, params: p, onApprove: onApprove, waiters: map[chan Outcome]bool{}}
		q.pending[fp] = it
		q.order = append(q.order, it)
		q.byKey[key]++
	}
	it.waiters[ch] = true
	it.asked++
	q.notifyLocked()
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	cancel := func() {
		q.mu.Lock()
		delete(it.waiters, ch)
		q.mu.Unlock()
	}
	return ch, cancel
}

// asks is how many requests waited on the item of fingerprint fp so far
// (0 when none is queued).
func (q *Queue) asks(fp string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if it := q.pending[fp]; it != nil {
		return it.asked
	}
	return 0
}

// queued reports whether an item of fingerprint fp is queued.
func (q *Queue) queued(fp string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pending[fp] != nil
}

// Pending is the number of queued items.
func (q *Queue) Pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

func (q *Queue) notifyLocked() {
	if q.onChange == nil {
		return
	}
	by := map[string]int{}
	for _, it := range q.pending {
		by[it.params.Container]++
	}
	q.onChange(len(q.pending), by)
}

// Run sends the queued items until ctx ends.
func (q *Queue) Run(ctx context.Context) {
	defer func() {
		q.answering.Wait()
		close(q.stopped)
	}()
	for {
		q.mu.Lock()
		var it *item
		if len(q.order) > 0 {
			it, q.order = q.order[0], q.order[1:]
			it.sent = true
			it.params.Pending = q.byKey[it.key]
			it.params.ClientGone = len(it.waiters) == 0
		}
		q.mu.Unlock()
		if it == nil {
			select {
			case <-ctx.Done():
				return
			case <-q.wake:
				continue
			}
		}
		if q.concurrent {
			q.answering.Add(1)
			go func() {
				defer q.answering.Done()
				q.answer(ctx, it)
			}()
		} else {
			q.answer(ctx, it)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// answer asks about one item and hands the outcome to its waiters.
func (q *Queue) answer(ctx context.Context, it *item) {
	var res wire.ApproveResult
	var err error
	if q.approve != nil {
		res, err = q.approve(ctx, it.fp, it.params)
	} else {
		res, err = q.console.Approve(ctx, it.params)
	}
	out := Outcome{Approved: err == nil && res.Approved, Auto: res.Auto}
	var ref *Refusal
	switch {
	case errors.As(err, &ref):
		out.Code, out.Reason, out.Ticket = ref.Code, ref.Reason, ref.Ticket
	case errors.Is(err, ErrNoConsole):
		out.Code, out.Reason = "E_NO_CONSOLE", "no lockhttp console is running"
	case err != nil:
		out.Code, out.Reason = "E_NO_CONSOLE", "the console did not answer: "+err.Error()
	}
	q.mu.Lock()
	delete(q.pending, it.fp)
	q.byKey[it.key]--
	if q.byKey[it.key] <= 0 {
		delete(q.byKey, it.key)
	}
	gone := len(it.waiters) == 0
	for ch := range it.waiters {
		ch <- out
	}
	q.notifyLocked()
	q.mu.Unlock()
	if out.Approved && it.onApprove != nil {
		it.onApprove(gone)
	}
}

// Grants holds what approvals open: connect grants (container × host ×
// port, for the policy's connect_grant), single-use authorisations
// (request fingerprint, 10 min) and redirect exemptions (container ×
// exact URL, 60 s, GET only).
type Grants struct {
	now func() time.Time

	mu       sync.Mutex
	connect  map[string]time.Time
	once     map[string]time.Time
	redirect map[string]time.Time
}

// SingleUseTTL is how long a single-use authorisation waits for its
// request.
const SingleUseTTL = 10 * time.Minute

// RedirectTTL is how long a listed CDN redirect target stays open.
const RedirectTTL = 60 * time.Second

// NewGrants returns empty grants.
func NewGrants(now func() time.Time) *Grants {
	return &Grants{now: now, connect: map[string]time.Time{}, once: map[string]time.Time{}, redirect: map[string]time.Time{}}
}

func (g *Grants) live(m map[string]time.Time, k string) bool {
	exp, ok := m[k]
	if ok && g.now().After(exp) {
		delete(m, k)
		return false
	}
	return ok
}

// GrantConnect opens container × host:port for d.
func (g *Grants) GrantConnect(container, hostport string, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.connect[container+"|"+hostport] = g.now().Add(d)
}

// Connect reports a live connect grant.
func (g *Grants) Connect(container, hostport string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.live(g.connect, container+"|"+hostport)
}

// GrantOnce adds a single-use authorisation for fingerprint fp.
func (g *Grants) GrantOnce(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.once[fp] = g.now().Add(SingleUseTTL)
}

// UseOnce consumes the single-use authorisation of fp.
func (g *Grants) UseOnce(fp string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.live(g.once, fp) {
		return false
	}
	delete(g.once, fp)
	return true
}

// GrantRedirect opens the exact URL for container's next GET.
func (g *Grants) GrantRedirect(container, url string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.redirect[container+"|"+url] = g.now().Add(RedirectTTL)
}

// UseRedirect consumes a redirect exemption.
func (g *Grants) UseRedirect(container, url string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := container + "|" + url
	if !g.live(g.redirect, k) {
		return false
	}
	delete(g.redirect, k)
	return true
}

// Sweep drops expired entries.
func (g *Grants) Sweep() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, m := range []map[string]time.Time{g.connect, g.once, g.redirect} {
		for k := range m {
			g.live(m, k)
		}
	}
}
