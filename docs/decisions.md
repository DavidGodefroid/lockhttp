# Decisions

The architecture review left a set of open questions for the user (D-optin,
D-console, D-ih, D-connect, D-body, D2, D3, D5, D6, D7, D8, D10). They were
not answered before v0.1.0, so each one takes the architect's recommended
option. Every decision below is revisable; the security requirements listed
first are not.

## Requirements (not negotiable)

| Requirement | Where it lives |
|---|---|
| The console runs **apart from the agent**, in its own account (`lockhttp`): since the Docker-only change (after v0.1.0) that account and its socket live in the image, the console in its own container (`lox run`'s service `lock-<lock>`, or `lockhttp-console` with the standalone launcher), the agent's containers never get its socket or its home volume. lockkit's isolation checks run against the image's root-owned `system.toml`. | `Dockerfile`, `scripts/lockhttp`, `lockhttp console` (lockkit `console.Run`) |
| **NeverAuto.** Every hub ticket is `NeverAuto`; an `auto` rule asks like `ask`. At parse time such a rule is valid only for a container (or all containers), never for an agent, and never in a production profile, for every host (`*`), for a spliced host, for messaging, for registry publishing, for `git-receive-pack` or for a write to any path of a git forge. Uploads, heuristic hits and secrets are checked per request. No auto mode answers a held request. | `internal/policy` (validation), `internal/gate` (hub tickets) |
| **A human decision is shared only by requests of identical fingerprint** (container, method, URL, every end-to-end header, normalised body). Requests under the same key but with another fingerprint are separate hub tickets, each approved on its own. | `internal/gate` (ask queue) |
| **Claude API path and body allowlist** once TLS is decrypted: `POST /v1/messages` and `/v1/messages/count_tokens` are free only when the body is one unambiguous JSON object without `mcp_servers` or `container` and with no server tool other than `web_search`; `/v1/files*` asks; OAuth paths and other body-less reads on the four Claude hosts are free; a credential that is not one of the container's is denied; any other write on the Claude hosts, and any other host under the Anthropic domains, asks (`NeverAuto`), unless the human lists that host as trusted (`docs.anthropic.com` is in the default set): then it is an ordinary trusted host. A policy rule naming a Claude host applies before the allowlist, and shadow mode lets its asks through. | `internal/decide/claude.go` |
| **Fail closed.** No console: an ASK is refused at once (`E_NO_CONSOLE`). An error while deciding, an unknown source, an unreadable source map: deny. A policy that does not decode counts as no console: FREE continues on the last policy, an ASK gets `E_NO_CONSOLE`; a policy whose fingerprint does not match is not installed and the previous one stays. The gate never reads a policy file; it only uses what the console serves. | `internal/gate` |

## Open decisions, recommended option taken

| ID | Question | Decision for v0.1.0 | Rationale |
|---|---|---|---|
| **D-optin** | Opt-in, and migration of `LEA_EGRESS_ALLOW`? | **Opt-in** (`LEA_LOCKHTTP=1` on the lea side). With LockHTTP on, squid's hard allowlist is switched off; `LEA_EGRESS_ALLOW` entries are migrated by hand, as trusted read-only hosts, with `lockhttp profile add --trusted`; squid's floor (DoH, IP literals, private ranges, ports) stays. Default after the shadow period. | A new egress path must earn trust before it becomes the default; the floor keeps the old guarantees. |
| **D-console** | Behaviour without a console | **FREE continues** on the last approved policy the gate holds in memory (or the built-in floor and Claude hosts when it never had one); **ASK is refused at once** with `E_NO_CONSOLE` and a page naming the command to run. | Availability of trusted reads without weakening anything that needs a human. |
| **D-ih** | Internal hosts | **Before** the private-range floor, as in squid today; decided at the domain (spliced); FREE only when marked `read`, ASK otherwise; on ports 80 and 443 and the ports their line declares. | Keeps lea's internal hosts working without making them a free channel. |
| **D-connect** | claude.ai connectors and `mcp_servers` | **No connector exception**; `mcp_servers` (and server tools other than `web_search`) on the API is **ASK, `NeverAuto`**. Connectors are switched off at the source by lea's managed settings. | The Claude API is a generic relay; every relay use needs a human. |
| **D-body** | Body preview on the screen | **Masked preview** (PII detectors + terminal sanitising, first 1 KiB) by default; never the clear body. | lockkit refuses clear results at level 1; the agent's account may read the window. |
| **D2** | Podman rootless without isolated gateway | **Accepted if the isolation test passes** (blocking test on the lea side, #115 option A). | Rootless Podman refuses the isolated gateway option. |
| **D3** | CA key in the gate or in a signer | **Separate signer** (`lockhttp signer`): it holds the CA key and issues leaf certificates over a Unix socket; the gate never sees the CA key. | A compromised gate cannot mint certificates beyond what it asks the signer for, and the key never sits in the data plane. |
| **D5** | Hold time and body limit | **60 s** hold, **10 MiB** buffer limit (`buffer_limit`), both in the policy. | Fits common client timeouts (git, npm, pip). |
| **D6** | lea deck notification | **A counter** of pending asks (lea side; the gate publishes pending counts in its status file); the first ASK plays no sound. | Draws the human to the hub without a card that could be mistaken for an approval channel. |
| **D7** | Concurrent approvals | **Side by side on the hub**: each held request is its own hub ticket, sent as it comes; identical requests share one. (Until the gate became hub-attached, it kept its own queue and sent one console approval at a time.) | No lockkit fork, no shared decisions. |
| **D8** | Initial trusted list | The set `lockhttp profile add` writes into `trusted` (`DocsTrusted`: Go, Python, npm, Rust, Debian, Ubuntu and Alpine package hosts, GitHub's read hosts, `developer.mozilla.org`, `docs.docker.com`, `kubernetes.io`, `man7.org`, `docs.anthropic.com`), plus the hosts given with `--trusted`. The four Claude hosts are built in, not in the list. Nothing adds OpenAI: trust it by hand if a provider uses it. | Small, read-only, human-reviewed at first start. |
| **D10** | WebFetch | **WebSearch allowed; WebFetch allowed** (its requests go through the gate and ask for unknown hosts); revisit after the shadow period. | WebSearch is server-side; WebFetch is visible to the gate. |

## Product choices made while building v0.1.0

- **One approval, three meanings.** An approval on the hub is a ticket the
  human approves or denies (with a reason). For a CONNECT (phase 1, or a spliced host) `y` opens
  container × host × port for `connect_grant` (10 min by default, a policy
  field); for a decrypted request `y` approves that request, and creates a
  single-use authorisation (container, method, URL, every end-to-end
  header, normalised body; 10 min) if the client already left. Durable openings are
  policy rules, written by the human and confirmed in `:review`.
- **Shadow mode** (`mode = "shadow"`) logs what would have asked or been
  denied, and lets it pass; the floor (IP literals, DoH, private ranges,
  ports, SNI mismatch, h2c, nested CONNECT), secret matches, the deny list
  and the company's managed rules stay enforced.
  `heuristics = "shadow"` (the default) does the same for the exfiltration
  score only.
- **Source map.** The container is read from the local address the
  connection arrived on (one proxy address per internal network), from a
  file lea writes; an address missing from the map is refused
  (`E_SOURCE_UNKNOWN`). `Proxy-Authorization` names the agent, for the
  audit only.
- **No MCP server.** Agents never talk to the console: they meet
  LockHTTP as a proxy, and its 403 pages say what to ask of the human.

## Hub-attached only (lockkit#110)

The gate runs hub-attached only: `lockhttp gate` needs `--hub`,
`--hub-key-file` and `--instance` (lea passes them from `lox run`'s
`up.json`) and exits otherwise ("launched by `lox run` only"). The
standalone gate, which asked a console of its own, and its rollback
(`E_WITHDRAWN`) are gone. `lockhttp console` stays: under `lox run` it serves
the approved policy to the gate and asks its human about every loosening;
it serves no approvals (`http.approve` and `--auto` are gone). One mode
keeps one path to test and to reason about (KISS).
