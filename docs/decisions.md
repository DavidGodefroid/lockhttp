# Decisions

The architecture review left a set of open questions for the user (D-optin,
D-console, D-ih, D-connect, D-body, D2, D3, D5, D6, D7, D8, D10). They were
not answered before v0.1.0, so each one takes the architect's recommended
option. Every decision below is revisable; the security requirements listed
first are not.

## Requirements (not negotiable)

| Requirement | Where it lives |
|---|---|
| The console runs **apart from the agent**, in its own account (`lockhttp`): since the Docker-only change (after v0.1.0) that account and its socket live in the image, the console in its own container (`lockhttp-console`), the agent's containers never get its socket or its home volume. lockkit's isolation checks run against the image's root-owned `system.toml`. | `Dockerfile`, `scripts/lockhttp`, `lockhttp console` (lockkit `console.Run`) |
| **NeverAuto by default.** Every approval screen is `NeverAuto` unless the request matched a rule with `verdict = "auto"`; such a rule is valid only for a container (or all containers), never for an agent, and never for a forbidden class (uploads, messaging, registry publishing, `git-receive-pack`, a spliced host, a heuristic hit, a secret, a production profile). The console re-checks the rule against its own approved policy before it lets auto mode answer. | `internal/policy` (validation), `internal/httpconsole` (re-check) |
| **A human decision is shared only by requests of identical fingerprint** (container, method, URL, significant headers, normalised body). Requests under the same key but with another fingerprint are separate items, each approved on its own. | `internal/gate` (ask queue) |
| **Claude API path and body allowlist** once TLS is decrypted: `POST /v1/messages` and `/v1/messages/count_tokens` are free only without `mcp_servers` and with no server tool other than `web_search`; `/v1/files*` asks; a credential that is not one of the container's is denied; any other host or path under the Anthropic domains asks (`NeverAuto`). | `internal/decide/claude.go` |
| **Fail closed.** No console: an ASK is refused at once (`E_NO_CONSOLE`). An error while deciding, an unknown source, an unreadable source map, a policy that does not decode: deny. The gate never reads a policy file; it only uses what the console serves. | `internal/gate` |

## Open decisions, recommended option taken

| ID | Question | Decision for v0.1.0 | Rationale |
|---|---|---|---|
| **D-optin** | Opt-in, and migration of `LEA_EGRESS_ALLOW`? | **Opt-in** (`LEA_LOCKHTTP=1` on the lea side). With LockHTTP on, `LEA_EGRESS_ALLOW` entries become trusted read-only domains and squid's hard allowlist is switched off; squid's floor (DoH, IP literals, private ranges, ports) stays. Default after the shadow period. | A new egress path must earn trust before it becomes the default; the floor keeps the old guarantees. |
| **D-console** | Behaviour without a console | **FREE continues** on the last approved policy the gate holds in memory (or the built-in floor and Claude hosts when it never had one); **ASK is refused at once** with `E_NO_CONSOLE` and a page naming the command to run. | Availability of trusted reads without weakening anything that needs a human. |
| **D-ih** | Internal hosts | **Before** the private-range floor, as in squid today; decided at the domain (spliced); FREE only when marked `read`, ASK otherwise; only on the ports their line declares. | Keeps lea's internal hosts working without making them a free channel. |
| **D-connect** | claude.ai connectors and `mcp_servers` | **No connector exception**; `mcp_servers` (and server tools other than `web_search`) on the API is **ASK, `NeverAuto`**. Connectors are switched off at the source by lea's managed settings. | The Claude API is a generic relay; every relay use needs a human. |
| **D-body** | Body preview on the screen | **Masked preview** (PII detectors + terminal sanitising, first 1 KiB) by default; never the clear body. | lockkit refuses clear results at level 1; the agent's account may read the window. |
| **D2** | Podman rootless without isolated gateway | **Accepted if the isolation test passes** (blocking test on the lea side, #115 option A). | Rootless Podman refuses the isolated gateway option. |
| **D3** | CA key in the gate or in a signer | **Separate signer** (`lockhttp signer`): it holds the CA key and issues leaf certificates over a Unix socket; the gate never sees the CA key. | A compromised gate cannot mint certificates beyond what it asks the signer for, and the key never sits in the data plane. |
| **D5** | Hold time and body limit | **60 s** hold, **10 MiB** buffer limit (`buffer_limit`), both in the policy. | Fits common client timeouts (git, npm, pip). |
| **D6** | lea deck notification | **Counter + sound on the first ASK** (lea side; the gate publishes pending counts in its status file). | Draws the human to the console without a card that could be mistaken for an approval channel. |
| **D7** | Serial lockkit approvals | **Accepted for v1**: the gate keeps its own queue and sends one approval at a time; concurrent approvals will be asked of lockkit later. | No lockkit fork, no shared decisions. |
| **D8** | Initial trusted list | lea's `EGRESS_DEFAULT` + Claude hosts (exact) + the docs set (`go.dev`, `pkg.go.dev`, `docs.python.org`, `developer.mozilla.org`, `docs.docker.com`, `kubernetes.io`, `man7.org`, `docs.anthropic.com`); **OpenAI only if a provider uses it**. | Small, read-only, human-reviewed at first start. |
| **D10** | WebFetch | **WebSearch allowed; WebFetch allowed** (its requests go through the gate and ask for unknown hosts); revisit after the shadow period. | WebSearch is server-side; WebFetch is visible to the gate. |

## Product choices made while building v0.1.0

- **One approval answer, three meanings.** lockkit's screen takes `y` or
  `n <reason>`. For a CONNECT (phase 1, or a spliced host) `y` opens
  container × host × port for `connect_grant` (10 min by default, a policy
  field); for a decrypted request `y` approves that request, and creates a
  single-use authorisation (container, method, URL, significant headers,
  normalised body; 10 min) if the client already left. Durable openings are
  policy rules, written by the human and confirmed in `:review`.
- **Shadow mode** (`mode = "shadow"`) logs what would have asked or been
  denied, and lets it pass; the floor (IP literals, DoH, private ranges,
  ports, SNI mismatch, h2c, nested CONNECT) and secret matches stay enforced.
  `heuristics = "shadow"` (the default) does the same for the exfiltration
  score only.
- **Source map.** The container is read from the local address the
  connection arrived on (one proxy address per internal network), from a
  file lea writes; an address missing from the map is refused
  (`E_SOURCE_UNKNOWN`). `Proxy-Authorization` names the agent, for the
  audit only.
- **No MCP server in v0.1.0.** Agents never talk to the console: they meet
  LockHTTP as a proxy, and its 403 pages say what to ask of the human.
