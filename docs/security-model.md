# LockHTTP security model

LockHTTP puts every outbound HTTP(S) request of an AI agent through a gate
that decides it with a policy only a human loosens, and holds what needs a
human until that human answers in a console the agent cannot reach. This
document says what it protects, how, and where it stops. It describes
v0.1.0.

## Principles

1. **Two planes.** The gate (data plane) carries the traffic and applies the
   policy; the console (control plane) holds the policy and the human's
   answers. The gate has no authority of its own: it never reads a policy
   file and cannot approve anything.
2. **The network is the boundary.** In lea the agent's container has no
   route out except the proxy container; proxy variables are a convenience.
3. **NeverAuto by default.** A human answers every ASK, unless an approved,
   active, container-scoped `auto` rule matches and the console agrees.
4. **The AI tightens, the human loosens.** A policy change that widens what
   passes without a human waits for the human's `:review`.
5. **Fail closed.** No console, an unknown source, an unreadable source map,
   an unparsable policy: nothing that needs a human goes through.
6. **Traced, without content.** Every decision is audited with its
   container, agent, task and session; never a body, a query string or a
   header value.

## Assets, attackers, scope

- **Assets:** the project's and the host's data, credentials (Claude, Git
  forges, cloud, registries), and actions taken online in the user's name
  (messages, pushes, publishes, API writes).
- **Attackers:** the agent itself (prompt injection, drift, a malicious
  dependency it runs), and hostile web content that steers it.
- **Out of scope:** a compromised host or console account, root, Anthropic
  itself, an attacker on the network upstream of the proxy container. A
  standalone gate whose agent can reach the network directly.

## Boundaries

| Boundary | Enforced by |
|---|---|
| Agent ↔ network | lea: the agent's container is on an `--internal` network whose only peer is the proxy container; squid listens on 127.0.0.1 only, so the gate is the only HTTP way out ([lea.md](lea.md) §2.2). |
| Agent ↔ gate | the gate reads the container from the local address the connection arrived on (one per internal network, `sources.json`); an unknown address is refused. The agent name (`Proxy-Authorization`) is recorded, not trusted. |
| Gate ↔ console | lockkit's Unix socket in `/run/lockhttp` (`2710 lockhttp:lockhttp-clients`), bind-mounted in the proxy container only; the console checks the peer's uid (`SO_PEERCRED`) against the clients group and `allowed_uids`; the gate refuses to run as root. |
| Console ↔ human | the console runs as `lockhttp`, in its own login session; lockkit refuses a console in the agent's account or in a container; approval screens in its own terminal, sanitised; 5 minutes without an answer is a denial. |
| Gate ↔ CA key | `lockhttp signer`, under its own uid, alone reads the key (refused if group- or world-readable) and issues 24-hour leaves over a Unix socket to allowed uids. |
| Policy | the console account's file, read by the console only, approved by fingerprint; the gate checks the fingerprint of what it receives. |

## Threats and parades

| # | Threat | Parade | Residual |
|---|---|---|---|
| T1 | The agent goes out directly, around the gate. | lea's `--internal` networks; squid on loopback only; keyproxy chained through the gate; SSH git forwarders refused with LockHTTP on (lea side). Direct mode refuses non-public addresses except internal hosts. | Depends on lea's network setup (rootless Podman without an isolated gateway: lea's isolation test, decision D2). Standalone mode has no such boundary. |
| T2 | Exfiltration through DNS (`<secret>.evil.com`). | The gate resolves a name only after the decision (direct mode), squid resolves after the gate; heuristics score long, deep and high-entropy labels. | The container's resolver is lea's (non-forwarding DNS is a lea requirement). Heuristics run in shadow by default. |
| T3 | DNS over HTTPS, IP literals, metadata endpoints, odd ports, `h2c`, nested `CONNECT`, SNI and Host spoofing. | The floor, which no policy loosens and shadow mode does not lift; a full ClientHello naming the `CONNECT` host is required on 443; the `Host` sent upstream is the decided host. | DoH hosts not on the list and not named `doh.*`/`dns.*` are decided like any host (unknown: ASK). |
| T4 | Exfiltration in reads to a trusted host (data in the URL or headers). | Decryption lets the gate see URLs and headers; secret formats are denied outside their hosts; the exfiltration score asks in `enforce`. | Without decryption the gate sees only the host. Low-bandwidth channels stay under the threshold. Heuristics are shadow by default. Spliced hosts are opaque. |
| T5 | A write to a trusted host (a webhook, an issue, a push). | Trusted means reads only: with decryption every non-read asks (`NeverAuto`, red for messaging, publishing, pushes), and a git push shows its refs. | **Without decryption, a trusted host is free at the domain, reads and writes**, and an approved `CONNECT` opens its host for `connect_grant`; the screen and the doctor say so. |
| T6 | The Claude API as a relay: `mcp_servers`, server tools, code execution containers, Files, a third-party key. | With decryption: the `/v1/messages` parameter allowlist, `/v1/files` asks, any other path or Anthropic host asks, credentials checked against the caller's list. | Without decryption the four Claude hosts are free at the domain. Prompt content sent to Anthropic is intended traffic. With no `credentials.json` the key check is off. |
| T7 | A secret leaving with a request. | Known formats (GitHub, Anthropic, AWS, Slack, OpenAI, Google, npm, GitLab, private keys) in the URL, headers or held body are denied outside their hosts, in shadow mode too. | Unknown formats, encoded or split secrets, and bodies over `buffer_limit` streamed by a `free` rule are not matched. Cookies are not scanned. |
| T8 | Approval fatigue. | Container-scoped `auto` rules for routine calls; identical requests share one screen; the pending count per container, method, host and path; a single-use authorisation after `E_PENDING` instead of a second screen. | The human factor. Requests with another body are separate screens, by design. |
| T9 | The agent manipulates the policy. | The policy lives in the console account's home; the gate only receives it; every loosening waits for `:review`; `auto` is refused on forbidden classes at parse time and re-checked by the console at approval time. | A human who approves a bad `:review`. |
| T10 | A compromised gate. | Dedicated non-root uid; no decision authority (the console re-checks auto claims and is the only one to approve); no CA key. | It sees and can alter FREE traffic and decrypted content; it can ask the signer for leaves for any valid host name while it runs; it can lie to the human about a request's content within the screen's bounds. |
| T11 | Theft of the CA key. | Only the signer reads it (`0600`, its own uid); CA `pathlen:0`, 90 days, trusted only in lea's containers; `lockhttp ca init --force` rotates. | Whoever holds the key can intercept traffic of containers that trust the CA until it expires or is rotated. |
| T12 | One agent impersonates another. | Rules apply to containers, never to agents; an agent token from another container is marked `ambiguous`. | Agents in one container share a uid: attribution within a container is declarative. |
| T13 | Replay or forgery of an approval. | A decision covers one fingerprint (container, method, URL, media type, every end-to-end header value hashed, normalised body); a single-use authorisation is consumed once and lives 10 minutes; a connect grant is per container × host × port. | During `connect_grant`, a `CONNECT` grant opens the host for any traffic of that container. |
| T14 | Prompt injection through the approval screen. | Every field the gate sends is bounded (512 B per field, 1 KiB preview, 16 warnings, 32 refs) and sanitised by lockkit; the preview is masked (personal data, credentials); the agent name is labelled "declared". | Text the human reads is still chosen in part by the agent (paths, body preview). |
| T15 | The console is absent or killed. | Every ASK is refused at once (`E_NO_CONSOLE`); FREE continues on the last approved policy. | Reduced availability, by design. |
| T16 | The console socket reachable by agents. | Bind-mounted in the proxy container only; `allowed_uids` holds the gate's uid; the clients group is the lea user's. | Processes running as the lea user on the host can reach the socket (they can ask, not approve). |

## Security requirements

These do not change with the policy ([decisions.md](decisions.md)):

- The console runs on the host, in its own account and login session.
- Every screen is `NeverAuto` unless an approved `auto` rule matches; the
  console re-checks that claim against its own approved policy (rule id,
  active, `auto`, allowed for its host and the profile, host, method, path,
  container, `max_body`, not spliced, not red, not a `CONNECT`).
- A human decision is shared only by requests of identical fingerprint.
- The Claude API is checked per path and parameter once decrypted.
- Fail closed: no console means every ASK is refused; an unknown source, an
  unreadable source map or an unreadable credentials file refuses; a policy
  whose fingerprint does not match is not installed.
- The gate never reads a policy; the signer alone holds the CA key.

## Residual risks and limits

- **Phase 1 (no decryption) decides at the domain.** A `CONNECT` to a
  trusted host or a Claude host is free and carries reads and writes; an
  approved `CONNECT` opens its host for the container for `connect_grant`.
  Rules with methods or paths, the secret scan, the heuristics and the
  Claude API allowlist need decryption.
- **Spliced and internal hosts are never decrypted.** Decide them knowing
  the gate sees only their names.
- **HTTP/1.1 only to clients when decrypting.** Clients that require HTTP/2
  fail rather than bypass.
- **A WebSocket session is one approval.** Frames after the upgrade are not
  inspected.
- **Heuristics are in shadow by default**, and shadow mode lets everything
  but the floor, secrets and the deny list through.
- **Grants skip the rules.** A single-use authorisation or a CDN redirect
  exemption is FREE without the rule and heuristic checks (the floor, the
  deny list and the secret check still apply); both are bound to one exact
  request or URL, one container, and a short life.
- **Serial approvals, one human.** The console answers one screen at a
  time; the gate queues the rest.
- **The agent name is declarative**, for the audit only.
- **Standalone mode** (no `--sources`) attributes every connection to
  `local` and depends on the agent honouring the proxy variables.
- **No external review** of LockHTTP has been done yet
  ([SECURITY.md](../SECURITY.md)).

Report a vulnerability privately: [SECURITY.md](../SECURITY.md).
