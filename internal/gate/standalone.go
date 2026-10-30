package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/DavidGodefroid/lockkit/plans"

	"github.com/DavidGodefroid/lockhttp/internal/decide"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// StandaloneReason is why a standalone start withdraws the plans of the
// gate's hub mode, as the plans store and then the hub record it.
const StandaloneReason = "the gate was restarted without its hub (standalone)"

// Withdrawn are the hub tickets a standalone start withdrew, by the
// fingerprint of their request: the gate refuses that request once,
// explicitly, rather than ask the console about a request the agent
// believes waits on the hub.
type Withdrawn struct {
	mu   sync.Mutex
	byFP map[string]string
}

// Tickets lists the withdrawn tickets not presented yet, sorted.
func (w *Withdrawn) Tickets() []string {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.byFP))
	for _, tk := range w.byFP {
		out = append(out, tk)
	}
	sort.Strings(out)
	return out
}

// take returns, and forgets, the withdrawn ticket of the request of
// fingerprint fp.
func (w *Withdrawn) take(fp string) (string, bool) {
	if w == nil {
		return "", false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	tk, ok := w.byFP[fp]
	delete(w.byFP, fp)
	return tk, ok
}

// withdrawnRefusal is the refusal of a request whose hub ticket this
// standalone start withdrew (once: sent again, the request is asked on the
// console like any other).
func (g *Gate) withdrawnRefusal(fp string) (decide.Decision, bool) {
	tk, ok := g.cfg.Withdrawn.take(fp)
	if !ok {
		return decide.Decision{}, false
	}
	return decide.Decision{Verdict: decide.Deny, Rule: "hub:withdrawn", Code: product.CodeWithdrawn,
		Reason: "withdrawn: the gate runs without its hub; ticket " + tk + " was withdrawn and nothing runs on it"}, true
}

// WithdrawStandalone is the rollback of hub mode (decision D.5), for a gate
// started without its hub flags: the plans every hub instance under
// hubDir (hubclient.KeyDir of the gate's home) left pending end Withdrawn,
// marked for the hub to hear of at the next start in hub mode
// (hubclient.Client.Sync). An instance whose plans another gate holds open
// (plans.ErrLocked: it runs in hub mode now) is left alone. It returns
// the withdrawn tickets by request, for Config.Withdrawn.
func WithdrawStandalone(hubDir string) (*Withdrawn, error) {
	w := &Withdrawn{byFP: map[string]string{}}
	dirs, err := filepath.Glob(filepath.Join(hubDir, "*", "plans"))
	if err != nil {
		return w, err
	}
	sort.Strings(dirs)
	var errs []error
	for _, d := range dirs {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
			continue
		}
		inst := filepath.Base(filepath.Dir(d))
		st, err := plans.Open(d)
		if errors.Is(err, plans.ErrLocked) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("hub plans of %s: %w", inst, err))
			continue
		}
		ws, err := st.WithdrawAll(StandaloneReason)
		if cerr := st.Close(); cerr != nil {
			errs = append(errs, cerr)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("hub plans of %s: %w", inst, err))
		}
		for _, pl := range ws {
			var b hubPlan
			if json.Unmarshal(pl.Body, &b) != nil || b.Fingerprint == "" || pl.Ticket == "" {
				continue
			}
			w.byFP[b.Fingerprint] = pl.Ticket
		}
	}
	return w, errors.Join(errs...)
}
