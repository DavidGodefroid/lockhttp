# The demo's capture

`scripts/brand/demo.py` draws `site/assets/demo.svg` (the README's and the
site's demo) from the files here. They are output of the code, but **not of
one run of a lea + `lox run` stack**: two runs, in two repositories, joined
by hand.

Sources: lockhttp `2f0d37f`, lockhub `4d94ef1`, both on lockkit `v0.20.0`.

## The files

| File | What it is | Produced by |
|---|---|---|
| `gate.txt` | The two `curl` commands, their output as curl printed it, then the gate's audit records. | Run 1 |
| `lox-run-idle.ans`, `lox-run-question.ans`, `lox-run-details.ans`, `lox-run-denied.ans` | The frames `lox run` drew, 80×26, with their colours (SGR): before the ticket, the question, the question after `d`, after `n`. | Run 2 |
| `loxrun_demo_test.go.txt` | The test of run 2. It belongs in lockhub, so it is kept here as text and is not built. | — |

## Run 1: the gate (this repository)

`internal/gate/democapture_test.go`, `TestDemoCapture`, skipped unless
`LOCKHTTP_DEMO_OUT` names a directory. Needs `curl`.

```sh
LOCKHTTP_DEMO_OUT=/tmp/capture go test ./internal/gate -run TestDemoCapture -count=1
```

It starts the gate of `internal/gate` as the package's tests do, with TLS
decryption, a `sources.json` as lea writes it (container `lea-ab12cd34ef`,
agent `dev-3`) and the policy `trusted = ["pkg.go.dev"]`, `hold = "60s"`.
Real `curl`, with `HTTPS_PROXY` set as lea sets it, sends the GET and the
POST. It writes `gate.txt` and `ticket.json`, the ticket the gate signed for
the held POST.

What is not the real thing in this run:

- **The hub is the test suite's fake hub.** It denies the ticket the way
  `lox run`'s `n` does, as run 2 showed: no reason, facade `tty` (the gate
  turns an empty reason into `denied on the hub`).
- **The upstream is a stand-in**, not pkg.go.dev: the `200` is the gate's
  answer for it.
- The connections are given the container's network address by the test
  (in lea, the proxy container has that address).

## Run 2: `lox run` (lockhub)

In a throwaway worktree of lockhub at `4d94ef1`:

1. In `internal/loxrun/e2e_test.go`: `inst = "shop"` becomes `"web"`, the
   size `100, 30` becomes `80, 26`, `Workspace: "~/e2e"` becomes
   `"~/Documents/shop"`.
2. Copy `loxrun_demo_test.go.txt` to `internal/loxrun/zz_demo_test.go`.
3. `LOCKHTTP_DEMO_OUT=/tmp/capture go test ./internal/loxrun -run TestLockhttpDemo -count=1`

It uses lockhub's e2e world: the real hub, a real lockkit hub client, and
`lox run` driven by key presses. It writes the four frames and
`decision.txt`, the hub's signed decision.

## The join

Run 2 does not receive run 1's ticket over the wire. It reads `ticket.json`
and **builds and signs a ticket again**, with the same risk, flags,
requester, header, body lines and warning, the way `internal/gate/hub.go`
does (`ticket.NewTicket`, `render.MaskScreen` with the same detectors),
under the lock key of lockhub's harness. So:

- the request id is the same on both sides, the ticket id is not;
- the clocks are those of two runs, a few seconds apart;
- the denial in `gate.txt` was given by run 1's fake hub, not by the `n`
  pressed in run 2.

## Typed in `demo.py`, not captured

The prompt, the two `curl` commands as shown, Claude Code's frame around a
command and its output (`● Bash(…)`, `└`, `Running…`), the pane titles, the
`FREE` / `ASK` / `403` badges, the two "you press…" hints (`lox run` does
not echo keys), the audit box's title and the three captions. The audit
lines are records of `gate.txt` with fields left out where they show `…`;
`gate.txt` holds a third record (`refused`, the answer sent to the agent)
that the demo does not show.
