# LockHTTP security model

LockHTTP puts every outbound HTTP(S) request of an AI agent running in
[lea](https://github.com/DavidGodefroid/lea) through a gate
that decides it with a policy only a human loosens, and holds what needs a
human until that human answers a ticket on lockhub, which the agent cannot
reach. This document says what it protects, how, and where it stops. It
describes the setup `lox run` starts (the hub and the lockhttp console) with
the gate lea runs ([how-it-works.md](how-it-works.md)); every command runs in
the image. The standalone launcher ([docker.md](docker.md)) names its
containers and volumes differently: `lockhttp-console`, `lockhttp-run`,
`lockhttp-home`.

## Principles

1. **Two planes.** The gate (data plane) carries the traffic and applies the
   policy; the console (control plane) holds the policy and asks the human
   about every loosening; the human answers held requests on lockhub. The
   gate has no authority of its own: it never reads a policy file and
   cannot approve anything; the console approves no request.
2. **The network is the boundary.** In lea the agent's container has no
   route out except the proxy container; proxy variables are a convenience.
3. **NeverAuto.** A human answers every ASK: every hub ticket of the gate is
   `NeverAuto`, and an `auto` rule asks like `ask`.
4. **The AI tightens, the human loosens.** A policy change that widens what
   passes without a human waits for the human's `:review`.
5. **Fail closed.** No console, an unknown source, an unreadable source map,
   an unparsable policy: nothing that needs a human goes through.
6. **Traced, without content.** The gate audits every decision with its
   container, agent, task and session; never a body, a query string or a
   header value. One exception: a decision's warnings, which can name the
   `mcp_servers` (names and URLs) found in a `/v1/messages` body.

## Assets, attackers, scope

- **Assets:** the project's and the host's data, credentials (Claude, Git
  forges, cloud, registries), and actions taken online in the user's name
  (messages, pushes, publishes, API writes).
- **Attackers:** the agent itself (prompt injection, drift, a malicious
  dependency it runs), and hostile web content that steers it.
- **Out of scope:** a compromised host or console account, root, any
  account that may run `docker` on the host (see
  [Docker](#what-docker-does-and-does-not-separate)), Anthropic itself, an attacker on the network upstream of the proxy container,
  and any agent that does not run inside lea: an agent started directly on
  the host never goes through the gate, so LockHTTP sees and protects none
  of its requests.

## Boundaries

| Boundary | Enforced by |
|---|---|
| Agent ↔ network | lea: the agent's container is on an `--internal` network whose only peer is the proxy container; squid listens on 127.0.0.1 only, so the gate is the only HTTP way out ([lea.md](lea.md) §2.2). |
| Agent ↔ gate | the gate reads the container from the local address the connection arrived on (one per internal network, `sources.json`); an unknown address is refused. The agent name (`Proxy-Authorization`) is recorded, not trusted. |
| Gate ↔ console | lockkit's Unix socket in `/run/lockhttp` (`2710 lockhttp:lockhttp-clients`), the socket volume (`<project>_<lock>-run` under `lox run`, `lockhttp-run` with the standalone launcher), mounted only in the console's and the gate's containers; the console checks the peer's uid (`SO_PEERCRED`) against the image's clients group (the `gate` account, uid 10003) and `allowed_uids` (empty unless the image is built with `ALLOWED_UIDS`); the gate refuses to run as root. |
| Console ↔ human | the console runs as `lockhttp` (uid 10021, not in the clients group) in `lox run`'s service `lock-<lock>` (`lockhttp-console` with the standalone launcher), with no log driver (no screen in `docker logs`); it is the only container with its home volume (`<project>_<lock>-home` under `lox run`, `lockhttp-home` standalone: the approved policy, the console's own log) and the profile's copy; its terminal shows only policy reviews, sanitised. |
| Gate ↔ human | each held request is a signed, `NeverAuto` hub ticket; the human approves or denies it on a lockhub facade (`lox approve`, lea's deck, a phone); the gate audits the outcome in its own JSONL. |
| Image's accounts | `lockhttp` (console, 10021), `gate` (10003, in `lockhttp-clients`, gid 10020), `signer` (10004); `/etc/lockhttp/system.toml` and the binary owned by root; the launcher on the host root-owned, running the image by the digest verified with cosign at install. |
| Gate ↔ CA key | at run time `lockhttp signer`, under its own uid, alone reads the key (refused if group- or world-readable) and issues 24-hour leaves over a Unix socket to allowed uids. Under lea the key is created and kept on the host in lea's data dir, then copied into the signer's volume. |
| Policy | the console account's file, read by the console only, approved by fingerprint; the gate checks the fingerprint of what it receives. |

## Threats and parades

| # | Threat | Parade | Residual |
|---|---|---|---|
| T1 | The agent goes out directly, around the gate. | lea's `--internal` networks; squid on loopback only; keyproxy chained through the gate; SSH git forwarders refused with LockHTTP on (lea side). Direct mode refuses non-public addresses except internal hosts. | Depends on lea's network setup (rootless Podman without an isolated gateway: lea's isolation test, decision D2). |
| T2 | Exfiltration through DNS (`<secret>.evil.com`). | Squid resolves after the gate; on decrypted or plain HTTP requests, heuristics score long, deep and high-entropy labels. | **With the hub's networks given (`--hub-net`, which lea always passes), the gate resolves every name that passes the floor before the decision**, to refuse the hub's addresses: a lookup of `<secret>.evil.com` leaves even when the request is then denied. The container's resolver is lea's (non-forwarding DNS is a lea requirement). A `CONNECT` decided at the domain is not scored. Heuristics run in shadow by default. |
| T3 | DNS over HTTPS, IP literals, metadata endpoints, odd ports, `h2c`, nested `CONNECT`, SNI and Host spoofing. | The floor, which no policy loosens (except `internal_hosts`, for their declared ports and single-label names) and shadow mode does not lift; a full ClientHello naming the `CONNECT` host is required on 443 for a non-internal host; the `Host` sent upstream is the decided host. | DoH hosts not on the list and not named `doh.*`/`dns.*` are decided like any host (unknown: ASK). |
| T4 | Exfiltration in reads to a trusted host (data in the URL or headers). | Decryption lets the gate see URLs and headers; secret formats are denied outside their hosts; the exfiltration score asks in `enforce`. | Without decryption the gate sees only the host. Low-bandwidth channels stay under the threshold. Heuristics are shadow by default. Spliced hosts are opaque. |
| T5 | A write to a trusted host (a webhook, an issue, a push). | Trusted means reads only: decryption covers `CONNECT` to port 443, where every non-read asks (`NeverAuto`, red for messaging, publishing, pushes), and a git push shows its refs. | **Without decryption, a trusted host is free at the domain, reads and writes**, and an approved `CONNECT` opens its host for `connect_grant`; the screen and the doctor say so. A `CONNECT` to port 80 of a trusted or Claude host is free at the domain and the plain HTTP inside is not decided: lea's squid refuses `CONNECT` to any port but 443, the gate alone does not. |
| T6 | The Claude API as a relay: `mcp_servers`, server tools, code execution containers, Files, a third-party key. | With decryption: the `/v1/messages` parameter allowlist, `/v1/files` asks, any other write or Anthropic host asks, credentials checked against the caller's list. | Without decryption the four Claude hosts are free at the domain. A policy rule naming a Claude host is applied before the allowlist, and shadow mode turns the allowlist's asks into FREE. Prompt content sent to Anthropic is intended traffic. With no `credentials.json` the key check is off. |
| T7 | A secret leaving with a request. | Known formats (GitHub, Anthropic, AWS, Slack, OpenAI, Google, npm, GitLab, private keys) in the URL, headers or held body are denied outside their hosts, in shadow mode too. | Unknown formats, encoded or split secrets, and bodies over `buffer_limit` streamed by a `free` rule are not matched. |
| T8 | Approval fatigue. | Container-scoped `free` rules for routine calls (confirmed with `:review`); identical requests share one screen; the pending count per container, method, host and path; a single-use authorisation after `E_PENDING` instead of a second screen. | The human factor. Requests with another body are separate screens, by design. |
| T9 | The agent manipulates the policy. | The policy lives in the console account's home; the gate only receives it; every loosening waits for `:review`; `auto` is refused on forbidden classes at parse time, and an `auto` rule only asks. | A human who approves a bad `:review`. |
| T10 | A compromised gate. | Dedicated non-root uid; no decision authority (every hub ticket it makes is `NeverAuto`; only a human approves on lockhub); no CA key. | It sees and can alter FREE traffic and decrypted content; it can ask the signer for leaves for any valid host name while it runs; it can lie to the human about a request's content within the screen's bounds. |
| T11 | Theft of the CA key. | At run time only the signer reads it (`0600`, its own uid); the host copy in lea's data dir stays on the host; CA `pathlen:0`, 90 days, trusted only in lea's containers; `lockhttp ca init --force` rotates. | Whoever holds the key can intercept traffic of containers that trust the CA until it expires or is rotated. |
| T12 | One agent impersonates another. | Rules apply to containers, never to agents; an agent token from another container is marked `ambiguous`. | Agents in one container share a uid: attribution within a container is declarative. |
| T13 | Replay or forgery of an approval. | A decision covers one fingerprint (container, method, URL, media type, every end-to-end header value hashed, normalised body); a single-use authorisation is consumed once and lives 10 minutes; a connect grant is per container × host × port. | During `connect_grant`, a `CONNECT` grant opens the host for any traffic of that container. |
| T14 | Prompt injection through the approval screen. | Every field the gate sends is bounded (512 B per field, 1 KiB preview, 16 warnings, 32 refs) and sanitised by lockkit; the preview is masked (personal data, credentials); the agent name is labelled "declared". | Text the human reads is still chosen in part by the agent (paths, body preview). |
| T15 | The console is absent or killed. | Every ASK is refused at once (`E_NO_CONSOLE`); FREE continues on the last approved policy. A policy that does not decode counts as no console; one whose fingerprint does not match is not installed, and the previous one stays. | Reduced availability, by design. |
| T16 | The console socket reachable by agents. | Besides the console, the socket volume is mounted in the gate's container only, never in an agent's; the clients group exists only in the image, where it holds the `gate` account; the agent gets neither the socket nor the Docker socket. | Any account that may run `docker` on the host can mount the socket volume, and more ([below](#what-docker-does-and-does-not-separate)). |
| T18 | In hub mode, a forged, replayed or misdirected decision; the agent reaching the hub. | A decision verifies under the pinned hub key only, must name this instance, the instance key and the ticket's plan hash (the request fingerprint), under the policy fingerprint in force; its nonce is consumed once and its pass once. The instance key lives in the gate's volume only. The gate refuses the hub's host name and its networks as targets, even with `internal_hosts`. A ticket's clear screen stays in the gate's volume and leaves only sealed: to a facade key pinned with `--facade-keys-file` (a reveal), or, with `--seal-clear`, to every device pinned with `--devices-file`; the hub relays ciphertext. A renewal of an expired ticket is re-checked against the policy in force, and a changed policy is a new ticket. | With `--upstream`, squid resolves names again after the gate: a name re-pointed into the hub's network between the gate's check and squid's lookup is not seen by the gate (squid's own rules and lea's networks still apply). |
| T17 | The agent edits the policy or the approved policy. | Both live in the console's volumes (its home and the profile's read-only copy under `lox run`, `lockhttp-home` with the standalone launcher), mounted only in the console account's containers, never by the gate or an agent; the project's `.lockhttp/config.toml`, which `profile add` writes and `lox run` copies, is only a proposal: any loosening in it still waits for `:review`. | An account that may run `docker` can open the console's home volume in a container of its own and change the approved policy. |
| T19 | A credential the agent holds leaks (its commands, logs, files, a request to another host). | Credential injection: the secret lives in the gate's secrets file (`0600`, the gate's container only), the policy names it only, and the gate adds the header after the verdict to one host and port, on a decrypted request or plain HTTP to an internal host; a request of the agent carrying the value (as is, URL-escaped, hex, base64 at any alignment), in its URL, headers, body, host (absolute URL, `Host`, `CONNECT` authority) or header names, is `E_SECRET_EGRESS` for every host (a value in a host or header name is refused before the floor, the hub's DNS check and the hub), with streamed and `gzip`/`deflate` bodies, WebSocket frames and plain tunnels scanned too (an encoding the gate cannot decode is refused); every response from a host and port with an injection (any path, any container) has the values redacted from its status, headers and body, with `Range`/`If-Range` removed and a partial response refused; TRACE to such a host is refused and no request to it upgrades; injections may be limited to methods and paths; the audit and the hub get the injection's name, never the value. | A compromised gate holds the values (T10). A value split across requests, frames or reads, or otherwise encoded by the agent, is not matched; a tunnel the gate does not decrypt is ciphertext; a target that transforms the credential before echoing it, or serves parts of it in separate responses through its own API, is not redacted; a value split over host names or written in punycode is not matched in the host ([policy.md](policy.md#credential-injection)). |

## Security requirements

These do not change with the policy ([decisions.md](decisions.md)):

- The console runs as its own account, in its own container, the only one
  with the console's home volume; the agent never gets the console's socket
  or the Docker socket.
- Every screen is `NeverAuto`: the gate runs hub-attached only, every hub
  ticket it makes is `NeverAuto`, and an `auto` rule asks like `ask`.
- A human decision is shared only by requests of identical fingerprint.
- The Claude API is checked per path and parameter once decrypted, unless
  a policy rule names the Claude host or the profile is in shadow mode.
- Fail closed: no console means every ASK is refused; an unknown source or
  an unreadable source map refuses; an unreadable credentials file denies
  every Claude credential; a policy whose fingerprint does not match is not
  installed.
- The gate never reads a policy; at run time the signer alone reads the CA
  key.

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
  decided; with injected secrets, the client's frames are scanned for them.
- **Heuristics are in shadow by default**, and shadow mode lets everything
  but the floor, secrets, the deny list and the company's managed rules
  through.
- **Grants skip the rules.** A single-use authorisation or a CDN redirect
  exemption is FREE without the rule and heuristic checks (the floor, the
  deny list and the secret check still apply); both are bound to one exact
  request or URL, one container, and a short life.
- **Approvals on the hub.** Each held request is a hub ticket a human
  answers on a facade; the gate never falls back to another approver.
- **The agent name is declarative**, for the audit only.
- **Docker is the separation**: see the next section.
- **No external review** of LockHTTP has been done yet
  ([SECURITY.md](../SECURITY.md)).

## What Docker does and does not separate

The gate's container reaches the console only through the socket in the
socket volume, as uid 10003; it holds no policy file and cannot approve.
lea's agent containers get neither the console's socket volume, nor its
home volume, nor the Docker socket, and reach the network only through the
gate. Under `lox run` these are `<project>_<lock>-run` and
`<project>_<lock>-home`, and the console is the service `lock-<lock>`; the
standalone launcher's are `lockhttp-run`, `lockhttp-home` and
`lockhttp-console`.

The Docker daemon is the residual boundary. Whoever can run `docker`
commands on the host (root, members of the `docker` group, the owner of a
rootless daemon) can:

- attach to the console's container and confirm a policy loosening;
- `docker exec` into the console's container, or read its memory;
- mount the console's home volume in another container and read or change
  the approved policy and the console's log;
- mount the socket volume and talk to the console as `gate`;
- run the gate's or the signer's container differently, or read the CA key
  given to the signer.

The console cannot see any of this: its terminal belongs to the container.
Keep the agent out of every account that may use Docker, and never give an
agent's container the Docker socket. lea's agents run in containers without
it.

Report a vulnerability privately: [SECURITY.md](../SECURITY.md).
