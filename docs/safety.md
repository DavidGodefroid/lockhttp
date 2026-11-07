# lockhttp safety model

The safety model in full. Threats, parades and residual risks: [security-model.md](security-model.md).

> Moved from the README, whole. `lox run` runs the hub and the lockhttp
> console, writes `.lockfamily/up.json` and serves the decisions in its
> terminal; it replaces lockhub's deprecated `lox up`.

## Security model

The gate is the enforcement point on the network path; the hub's facades
are the only place a human decision about a request is made, and the
console the only place a loosening of the policy is. In short:

- **The console is in its own container, under its own account.**
  `lockhttp console` runs as `lockhttp` (uid 10021) in `lox run`'s service,
  without a log driver. Its socket is reachable only by the
  `lockhttp-clients` group (the image's `gate` account), checked with the
  kernel's peer credentials, and its socket volume is mounted in the
  gate's container only, never in an agent's. Anyone who can run
  `docker` on the host can reach the console's container and volumes: keep
  the agent away from the Docker socket.
- **NeverAuto.** Every hub ticket of the gate is `NeverAuto`: the hub
  cannot check an `auto` rule against the console's policy (a rule that asks
  like `ask`), so
  nothing answers a held request but a human. Secrets are denied.
- **A decision is shared only by identical requests.** Same container,
  method, URL, significant headers and normalised body; anything else is
  its own screen.
- **Hub-attached only.** The gate does not start without its hub flags,
  and nothing falls back to another approver when the hub is unreachable:
  the ticket stays pending until the hub answers.
- **Fail closed.** No console: every ASK is refused at once
  (`E_NO_CONSOLE`), while FREE goes on with the last policy the console
  served. Unknown source, unreadable source map: refused. An unreadable
  credentials file: every Claude credential is denied. A policy whose
  fingerprint does not match: the previous one is kept.
- **The gate never reads a policy.** It uses what the console serves, and
  checks it against the console's fingerprint.
- **The signer holds the CA key.** The gate asks `lockhttp signer` for a
  24-hour leaf per host, over a Unix socket restricted to allowed uids; it
  never sees the CA key.
- **The AI tightens, the human loosens.** Any change that widens what passes
  without a human (a trusted host, a `free` rule, shadow mode, a
  longer grant, a removed deny...) waits for your `:review`.
- **Traced.** The gate's JSONL audit and the console's audit carry
  `request_id`, `container`, `agent`, `attribution`, `via`, never a body, a
  query string or a header value.

Threats, parades and residual risks: [docs/security-model.md](security-model.md).
