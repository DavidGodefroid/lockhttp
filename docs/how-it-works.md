# How lockhttp works

Why per-request decisions; the gate, the console and the hub; the verdicts; what the agent sees; the Claude API checks; the limits. The short version is in the [README](../README.md#how-it-works).

> Moved from the README, whole. `lox run` runs the hub and the lockhttp
> console, writes `.lockfamily/up.json` and serves the decisions in its
> terminal; it replaces lockhub's deprecated `lox up`.

## Why LockHTTP?

An agent that can read the web can also write to it: a `POST` to a webhook,
a `git push`, a package publish, a secret tucked into a query string, a
Claude API call that hands an MCP server to the model. An allowlist of
domains does not tell these apart from a documentation read, and approval
prompts inside the agent's own process can be configured away by that
process.

LockHTTP moves the decision out of the agent and onto the network path:

| | Domain allowlist | In-agent approval | LockHTTP |
|---|:---:|:---:|:---:|
| Reads of trusted hosts pass without a prompt | ✅ | ✅ | ✅ |
| A write to a trusted host still needs a human | ❌ | ✅ | ✅ (per request when decrypting) |
| Approval cannot be switched off from the agent side | ✅ | ❌ | ✅ |
| Policy loosening needs a human confirmation | ❌ | ❌ | ✅ |
| Secrets sent to the wrong host are refused | ❌ | ❌ | ✅ (when decrypting) |
| Claude API relays (`mcp_servers`, server tools, Files) need a human | ❌ | ❌ | ✅ (when decrypting) |
| Each decision traced to container, agent, task | ❌ | ❌ | ✅ |

## How it works

Three pieces, each in a container of its own, and the hub. Only the
policy the console serves decides what needs a human, and only the human
answers, on the hub. LockHTTP runs hub-attached only: `lox run` runs its
console and the hub, and lea runs the gate with the hub flags `lox run`
hands it.

```
 agent container  (internal network only, no route out)
   HTTP(S)_PROXY=http://<agent>:<token>@lea-proxy:3130
          │
          ▼
 gate container   (shares the proxy container's network)
   lockhttp gate :3130   (uid 10003 "gate", never root)  ──▶  squid 127.0.0.1:3128  ──▶  Internet
   lockhttp signer       (its own container, uid 10004, holds the CA key; only with decryption)
          │  socket volume <project>_<lock>-run: /run/lockhttp/user-<profile>.sock
          │  (gate and console only; peer uid checked by the kernel)
          ▼
 console container  (lox run's service lock-<lock>, its terminal)
   uid 10021 "lockhttp" · the policy, the approved policy, the audit
   serves the approved policy to the gate · asks you about every loosening
          ·
 gate ──▶ lockhub (lox run's hub network; only lea's proxy joins it)
   held requests become signed tickets · you approve on a facade (lox approve, lea's deck, a phone)
```

1. The agent's HTTP client sends every request to the **gate**, a Go
   HTTP(S) proxy. In [lea](https://github.com/DavidGodefroid/lea) the agent's
   container has no other route out: the proxy variables are a convenience,
   the network is the boundary.
2. The gate decides each request with the policy the **console** serves it
   (`policy.get`, polled every 2 s). It never reads a policy file.
3. A request that is free goes out through squid, which keeps its own floor
   (DoH, IP literals, private ranges, ports). A request that needs a human
   is held (60 s by default) as a signed ticket on the hub, where you
   approve or deny it.
4. With a local CA and the **signer**, the gate decrypts HTTPS and decides
   each request by method, path, headers and body. Without them, it decides
   a `CONNECT` at the domain only (see [Limits](#limits)).

### Verdicts

| Verdict | What happens |
|---|---|
| **FREE** | The request goes out. The gate audits it (JSONL, one file per day). |
| **ASK** | The gate holds the request and asks the hub: a ticket you approve or deny (with a reason) on a facade. Every ticket is `NeverAuto`: the hub has no auto mode for the gate's asks. |
| **DENY** | `403` with an `X-LockHTTP-Code` header, at once. |

What an ASK becomes depends on what the gate sees:

- **A `CONNECT` decided at the domain** (no decryption, or a spliced or
  internal host): `y` opens *container × host × port* for `connect_grant`
  (10 minutes by default), **for reads and writes**, content unseen. The
  screen says so.
- **A decrypted or plain HTTP request**: `y` approves that request. If the
  agent's client already gave up (hold time passed, `E_PENDING`), `y` creates
  a single-use authorisation for the identical request, valid 10 minutes.
- **Durable openings** are policy rules, which you write and confirm in the
  console's `:review`.

Requests of identical fingerprint
(container, method, URL, media type, every end-to-end header,
normalised body) share one screen and one decision; a request to
the same URL with another body is a separate screen.

## What the agent sees

A refusal is a `403 Forbidden` with a plain-text body that says why and
what to ask of the human, and two headers: `X-LockHTTP-Code` and
`X-LockHTTP-Request` (the id to find in the console and the audit). For a
`CONNECT` it is the `CONNECT`'s own response, which clients show as a proxy
error. In hub mode an `E_PENDING` also names the hub ticket the request
waits on (`X-LockHTTP-Ticket`). A forwarded response carries `X-LockHTTP-Request` too (decrypted or
plain HTTP); a target the gate cannot reach is a `502`.

| Code | Meaning | What the agent should do |
|---|---|---|
| `E_PENDING` | The request waits for the human past the hold time. | Retry the same request in a moment: once approved it goes through. |
| `E_NO_CONSOLE` | No console is running: every ASK is refused at once. | Ask the user to run `lox run`. |
| `E_DENIED` | The human denied it (the reason is in the body). | Do not retry; ask the user. |
| `E_TIMEOUT` | The hub ticket expired before anyone answered it (the ticket is in `X-LockHTTP-Ticket`). | Send the same request again: it is asked again. |
| `E_RULE` | A deny rule or the deny list refuses it. | Ask the user to change the rule. |
| `E_FLOOR` | The network floor: IP literal, DoH, cloud metadata, port, single-label host, SNI or Host mismatch, `h2c`, nested `CONNECT`, a non-absolute URL. | Use a named public host on 80 or 443. |
| `E_SECRET_EGRESS` | A known credential sent outside its own hosts, a Claude credential that is not the container's, or the value of a secret the gate injects. | Never send a credential to another host. |
| `E_BODY_TOO_LARGE` | The body is over `buffer_limit` and cannot be held for a human. | Send less, or ask for a rule. |
| `E_SOURCE_UNKNOWN` | The gate cannot tell which container sent the request. | Use the proxy address lea gave. |
| `E_INJECT` | The policy injects a credential for this host, and the gate's secrets file lacks it or does not load. | Ask the user to check the gate's secrets file; never send the credential yourself. |

`E_HOST_UNKNOWN`, `E_CLAUDE_API_PARAM`, `E_EXFIL_SUSPECT`, `E_METHOD` and
`E_PINNED` are registered codes too; in v0.1.0 a refused ASK reaches the
agent as `E_DENIED`, `E_TIMEOUT`, `E_PENDING` or `E_NO_CONSOLE`, and
`E_PINNED` appears in the gate's audit only (a client that rejects the
gate's certificate closes the connection before any response).

## Claude API allowlist

The four hosts Claude Code reaches (`api.anthropic.com`, `claude.ai`,
`console.anthropic.com`, `statsig.anthropic.com`) are free at the domain.
Any other host under `anthropic.com`, `claude.ai` or `claude.com` asks
(`NeverAuto`), unless a rule says otherwise.

Once TLS is decrypted, the Claude API is a generic relay and is checked per
request:

| Request | Verdict |
|---|---|
| `POST /v1/messages`, `/v1/messages/count_tokens` | FREE only when the body is one unambiguous JSON object with no `mcp_servers`, no `container`, and no server tool other than `web_search` (custom tools and the client-run `bash`, `text_editor`, `computer`, `memory` are fine). Otherwise ASK, red, `NeverAuto`. |
| OAuth paths (`/v1/oauth/`, and `/oauth/` on `claude.ai`) | FREE |
| `/v1/files*` | ASK, `NeverAuto` |
| Other reads on the four hosts | FREE |
| Other writes | ASK, `NeverAuto` |
| A credential (`Authorization`, `x-api-key`) not in the caller's list, or two credentials | DENY `E_SECRET_EGRESS` (with lea's `credentials.json`) |

Duplicate keys, and keys that differ from `mcp_servers`, `tools` or
`container` only by case, make the body ambiguous: it asks.

## Limits

- **Without decryption, a `CONNECT` opens reads AND writes.** A trusted host
  is free at the domain, and an approved `CONNECT` opens its host for
  `connect_grant`; the gate does not see what goes through. Rules with
  `methods` or `path` cannot apply at the domain. The Claude API allowlist
  needs decryption too. `lockhttp doctor` warns when no CA is given.
- **HTTP/1.1 only to clients when decrypting.** The gate offers ALPN
  `http/1.1`; it does not speak HTTP/2 to clients, and refuses `Upgrade: h2c`.
- **A WebSocket session is one approval.** The upgrade request is decided;
  the frames that follow are not.
- **Heuristics run in shadow by default.** The exfiltration score is logged,
  not enforced, until you set `heuristics = "enforce"`.
- **Asks wait side by side.** Each held request is its own hub ticket;
  identical requests share one.
- **The agent name is declarative.** The container is read from the network
  the connection arrived on; the agent name comes from `Proxy-Authorization`
  and is for the audit only. Agents of one container share a uid, so rules
  scope to containers, never to agents.
- No MCP server in v0.1.0: agents meet LockHTTP as a proxy, and its `403`
  pages tell them what to ask of the human.
