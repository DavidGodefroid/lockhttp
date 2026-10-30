package gate

import (
	"context"
	"errors"
	"sync"

	"github.com/DavidGodefroid/lockkit/client"
	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/lockhttp/internal/product"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// ErrNoConsole means no console answers.
var ErrNoConsole = errors.New("no lockhttp console is running")

// Console is the gate's view of the console: the approved policy and the
// human's answers.
type Console interface {
	Policy(ctx context.Context) (wire.PolicyResult, error)
	// Approve returns nil when approved; a *Refusal when the human (or the
	// timeout) refused; ErrNoConsole when no console answers.
	Approve(ctx context.Context, p wire.ApproveParams) (wire.ApproveResult, error)
}

// Refusal is a console's refusal of an approval.
type Refusal struct {
	Code   string
	Reason string
	// Ticket is the hub ticket the refusal is about (hub mode), "" for
	// none.
	Ticket string
}

func (r *Refusal) Error() string { return r.Reason }

// LockkitConsole dials the console with lockkit's client: one connection
// for the policy poll, one for approvals (the console is serial: a poll
// queued behind an approval simply waits).
type LockkitConsole struct {
	Profile string
	// Cwd is where the client looks for a project (none: "/").
	Cwd string

	mu   sync.Mutex
	conn map[string]*client.Client
}

var _ Console = (*LockkitConsole)(nil)

func (c *LockkitConsole) get(slot string) (*client.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		c.conn = map[string]*client.Client{}
	}
	if cl := c.conn[slot]; cl != nil {
		return cl, nil
	}
	cwd := c.Cwd
	if cwd == "" {
		cwd = "/"
	}
	cl, err := client.Dial(product.P, cwd, c.Profile)
	if err != nil {
		if errors.Is(err, client.ErrNoConsole) {
			return nil, ErrNoConsole
		}
		return nil, err
	}
	cl.Name = "lockhttp-gate"
	c.conn[slot] = cl
	return cl, nil
}

func (c *LockkitConsole) drop(slot string, cl *client.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn[slot] == cl {
		delete(c.conn, slot)
	}
	_ = cl.Close()
}

func (c *LockkitConsole) call(ctx context.Context, slot, method string, params, result any) error {
	cl, err := c.get(slot)
	if err != nil {
		return err
	}
	err = cl.Call(ctx, method, params, result)
	var rpc *ipc.RPCError
	if err != nil && !errors.As(err, &rpc) {
		// Transport error: the console left; dial again next time.
		c.drop(slot, cl)
		if errors.Is(err, client.ErrConsoleClosed) {
			return ErrNoConsole
		}
	}
	return err
}

// Policy implements Console.
func (c *LockkitConsole) Policy(ctx context.Context) (wire.PolicyResult, error) {
	var r wire.PolicyResult
	err := c.call(ctx, "policy", wire.MethodPolicy, nil, &r)
	return r, err
}

// Approve implements Console.
func (c *LockkitConsole) Approve(ctx context.Context, p wire.ApproveParams) (wire.ApproveResult, error) {
	var r wire.ApproveResult
	err := c.call(ctx, "approve", wire.MethodApprove, p, &r)
	var rpc *ipc.RPCError
	if errors.As(err, &rpc) {
		switch rpc.Code {
		case ipc.CodeDenied:
			return r, &Refusal{Code: string(product.CodeDenied), Reason: rpc.Message}
		case ipc.CodeTimeout:
			return r, &Refusal{Code: string(product.CodeTimeout), Reason: rpc.Message}
		default:
			return r, &Refusal{Code: string(product.CodeDenied), Reason: "the console refused: " + rpc.Message}
		}
	}
	if err == nil && !r.Approved {
		return r, &Refusal{Code: string(product.CodeDenied), Reason: "not approved"}
	}
	return r, err
}
