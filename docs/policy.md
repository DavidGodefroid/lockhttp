# LockHTTP policy reference

The policy is the profile the human writes in the console account's config
file, `~/.config/lockhttp/config.toml` (`lockhttp init` writes a first
one). The console reads it, validates it, has you approve it, and serves
the approved policy to the gate (`policy.get`) with its sha256 fingerprint.
**The gate never reads a policy file**: it uses what the console serves,
checks the fingerprint, and keeps the previous policy when they do not
match.

This page documents v0.1.0 as the code implements it
(`internal/policy`, `internal/decide`, `internal/gate`).

## File format

TOML, one table per profile:

```toml
[profiles.default]
production    = false
mode          = "enforce"
heuristics    = "shadow"
buffer_limit  = "10MiB"
hold          = "60s"
connect_grant = "10m"
idle_timeout  = "24h"
max_session   = "24h"
trusted       = ["go.dev", "*.readthedocs.io"]
splice        = []
deny          = []
redirect_cdn  = []

[[profiles.default.internal_hosts]]
host  = "git.corp.example"
ports = [8443]
read  = true

[[profiles.default.rules]]
id        = "npm-audit"
container = "lea-ab12cd34ef"
host      = "registry.npmjs.org"
methods   = ["POST"]
path      = "/-/npm/v1/security/advisories/bulk"
verdict   = "auto"
max_body  = "256KiB"
expires   = "2026-12-31"
note      = "npm audit in the shop container"
```

An unknown key is refused, as is any key or value that looks like a secret
(a DSN with an embedded password, a control or formatting character).
Profile names use letters, digits, `_`, `-` and `.`, starting with a letter
or digit (at most 64 bytes); a production profile's name must be at least 2
characters and not `y`, `yes`, `n`, `no` or `ok`.

## Profile keys

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `production` | bool | `false` | No rule may have `verdict = "auto"`; the console treats the profile as production. |
| `mode` | string | `"enforce"` | `"enforce"` or `"shadow"`. See [Shadow mode](#shadow-mode). |
| `heuristics` | string | `"shadow"` | `"enforce"`, `"shadow"` or `"off"`. See [Exfiltration heuristics](#exfiltration-heuristics). |
| `buffer_limit` | size | `"10MiB"` | Largest body the gate holds for a human. `"512B"`, `"256KiB"`, `"10MiB"`, `"1GiB"` or a number of bytes; more than 0, at most 1 TiB. |
| `hold` | duration | `"60s"` | How long the gate holds a request for the human before answering `E_PENDING`. Go duration, at least `1s`, at most `5m` (the console's approval timeout). |
| `connect_grant` | duration | `"10m"` | How long an approved `CONNECT` opens container × host × port. At least `1s`. |
| `idle_timeout` | duration | `"24h"` | The console session's idle limit (lockkit). At least `1s`. |
| `max_session` | duration | `"24h"` | The console session's total limit (lockkit). At least `1s`. |
| `trusted` | host list | `[]` | Reads of these hosts are free; at the domain (no decryption), a `CONNECT` to them is free. |
| `splice` | host list | `[]` | Never decrypted: a `CONNECT` to them is decided at the domain, even when the gate decrypts. For clients that pin certificates. |
| `deny` | host list | `[]` | Always refused (`E_RULE`). |
| `redirect_cdn` | list of `"origin>cdn"` | `[]` | A 3xx from `origin` whose `Location` is on `cdn` lets the same container `GET` that exact URL once, without a body, within 60 s. Both sides are host patterns. |
| `internal_hosts` | array of tables | `[]` | See [Internal hosts](#internal-hosts). |
| `rules` | array of tables | `[]` | See [Rules](#rules). |

Built-in `redirect_cdn` pairs, always active:

```
ghcr.io>pkg-containers.githubusercontent.com
github.com>objects.githubusercontent.com
github.com>release-assets.githubusercontent.com
github.com>codeload.github.com
api.github.com>codeload.github.com
registry-1.docker.io>production.cloudflare.docker.com
proxy.golang.org>storage.googleapis.com
pypi.org>files.pythonhosted.org
```

### Host patterns

- `example.com`: that host only.
- `*.example.com`: any subdomain of `example.com`, not `example.com`
  itself.
- `*`: any host. Only in a rule's `host`.

Hosts are lower-cased and a trailing dot is dropped. A host must have at
least two labels (except an internal host), each a valid DNS label; IP
literals are refused everywhere.

### Internal hosts

```toml
[[profiles.default.internal_hosts]]
host  = "git.corp.example"   # an exact name, may be single-label ("gitlab")
ports = [443, 8443]          # required, 1-65535
read  = true                 # default false
```

An internal host is an exact name (a `*.` pattern is refused). It may resolve to a private address, and may use the ports
it lists (any other host is limited to 80 and 443). It is never decrypted:
a `CONNECT` to it is decided at the domain. With `read = true`, a
`CONNECT` and a read are free; otherwise every request asks (`NeverAuto`).

### Rules

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique in the profile. 1-64 characters: letters, digits, `_`, `-`, `.`, starting with a letter or digit. |
| `container` | no | The container it applies to (lea's container name, `local` without a `sources.json`); empty: every container. |
| `agent` | | **Refused.** An agent name is declarative; rules apply to a container or to all. |
| `host` | yes | A host pattern, or `*`. |
| `methods` | no | HTTP methods (upper-cased); empty: every method. |
| `path` | no | An exact path, or a prefix when it ends with `*` (`/v1/items*`); must start with `/`; empty: every path. Matched against the escaped path, without the query string. |
| `verdict` | yes | `free`, `auto`, `ask` or `deny`. |
| `max_body` | no | Size: a body larger than this turns the rule's verdict into ASK, `NeverAuto`. `0` or absent: the `buffer_limit`. |
| `expires` | no | `YYYY-MM-DD`: the last day (UTC) the rule applies. Absent: never expires. |
| `note` | no | Free text for you. |

| Verdict | Effect when the rule decides |
|---|---|
| `free` | FREE. |
| `auto` | ASK. The gate asks lockhub, which has no auto mode for its asks: an `auto` rule asks like `ask` (see below). |
| `ask` | ASK, `NeverAuto`. |
| `deny` | DENY, `E_RULE`. |

`verdict = "auto"` is refused when the file is parsed if the profile is
production, the host is `*`, the host is spliced, the host sends messages
(Slack, Gmail API, Microsoft Graph and Outlook, Discord, Telegram, Twilio,
SendGrid, Mailgun, Postmark, Pushover, ntfy, webhook.site, Office
webhooks), the rule's methods can publish to a package or image registry
(npm, PyPI, crates.io, RubyGems, Docker Hub, GHCR, Quay, `*.pkg.dev`,
`*.azurecr.io`, NuGet, Maven Central, `uploads.github.com`), the path
contains `git-receive-pack`, or the rule allows a write to any path of
`github.com`, `gitlab.com`, `bitbucket.org` or `codeberg.org`.

The gate runs hub-attached only, and every hub ticket it makes is
`NeverAuto`: the hub cannot check an `auto` rule against the console's
policy, so a human answers every held request, `auto` rule or not. The
verdict stays valid in a policy file (and keeps the checks above).

## Evaluation order

For each connection, then each request, the first step that decides wins.

### At the gate, before the policy

1. **Source.** With `--sources`, the container is the one whose network
   owns the local address the connection arrived on; a connection on
   127.0.0.1 must carry the keyproxy token and name a known container in
   `X-Lea-Source`. Anything else: `E_SOURCE_UNKNOWN`. Without `--sources`,
   every connection is container `local`.
2. **Request shape.** A non-`CONNECT` request must use an absolute
   `http://` URL whose `Host` header matches; inside a decrypted tunnel the
   `Host` header must match the `CONNECT` host. Otherwise `E_FLOOR`.

### The floor (no policy loosens it)

3. In this order: no host; an IP literal; a cloud metadata name
   (`metadata`, `metadata.google.internal`, `metadata.goog`,
   `instance-data`, `instance-data.ec2.internal`); DNS over HTTPS (a host
   starting with `doh.` or `dns.`, a known DoH provider, and for a request a
   path ending `/dns-query`, `/resolve?name=` or an `application/dns-message`
   type); a `CONNECT` inside a tunnel; a TLS server name that differs from
   the `CONNECT` host; `Upgrade: h2c`; a port other than 80 and 443, unless
   it is one of an internal host's ports; a single-label host that is not an
   internal host. All `E_FLOOR`.

### `CONNECT` routing

4. A `CONNECT` to port 443 of a host that is neither spliced nor internal,
   when the gate decrypts (`--ca-cert` and `--signer`): the deny list is
   checked (`E_RULE`), then the tunnel is decrypted and each request inside
   goes through steps 6 onwards. The gate offers HTTP/1.1 only.
5. Any other `CONNECT` is decided at the domain: a live connect grant for
   container × host × port is FREE; otherwise steps 7 onwards decide, with
   no method, path or body known. Once open, the client's first bytes must
   be a complete TLS ClientHello naming the host on port 443 (a ClientHello
   on other ports must name it too), or the tunnel is closed.

### Grants (decrypted or plain HTTP requests)

6. First the deny list and the secret check (steps 7 and 8) apply: no
   grant lifts them. Then a single-use authorisation for this exact request fingerprint (created
   when you approved a request whose client had left) is FREE and consumed.
   A `GET` without body of an exact URL a listed CDN redirect opened for
   this container within 60 s is FREE and consumed.

### The policy (`internal/decide`)

7. **Deny list.** A host on `deny`: DENY `E_RULE`.
8. **Secrets** (requests only, not a `CONNECT`). A known credential format
   in the path, query (raw and unescaped), header values (except `Cookie`)
   or held body, sent to a host it does not belong to: DENY
   `E_SECRET_EGRESS`. Formats: GitHub tokens (GitHub hosts), Anthropic API
   keys (`api.anthropic.com`, `console.anthropic.com`), AWS access keys
   (`*.amazonaws.com`), Slack tokens (Slack), OpenAI keys
   (`api.openai.com`), Google API keys (`*.googleapis.com`), npm tokens
   (`registry.npmjs.org`), GitLab tokens (GitLab), and private keys (no host).
9. **Internal hosts.** An internal host with `read = true`: FREE for a
   `CONNECT` or a read. Any other request to an internal host: ASK,
   `NeverAuto`.
10. **Exfiltration score** (requests only, unless `heuristics = "off"`):
    computed now, applied in step 15.
11. **Rules, most specific first.** Among the rules that are active (not
    past `expires`), whose host pattern matches, whose `container` is empty
    or the caller's, and whose methods and path match the request, the one
    with the highest specificity decides. At the domain (a `CONNECT`), only
    rules without `methods` and without `path` take part. Specificity adds:

    | Part of the rule | Points |
    |---|---|
    | a `container` | 1000 |
    | an exact host | 400 + its length |
    | a `*.domain` host | 100 + its length |
    | `*` | 0 |
    | an exact path | 300 |
    | a prefix path (`/x*`) | 50 + its length (at most 240, so always below an exact path) |
    | `methods` | 10 |

    So a container rule beats an all-containers rule, an exact host beats a
    wildcard, an exact path beats a prefix, a longer prefix beats a shorter
    one, and listed methods beat none. On a tie, the rule whose `id` sorts
    first wins. A rule decides whatever its verdict: a more specific `free`
    rule wins over a less specific `deny` rule.

    Body limits of a rule (requests only): a body larger than `max_body`
    turns the verdict into ASK, `NeverAuto`; a body larger than
    `buffer_limit` is DENY `E_BODY_TOO_LARGE` unless the verdict is `free`
    (only a `free` rule may stream a body over the buffer limit).
12. **Anthropic domains.** A host under `anthropic.com`, `claude.ai` or
    `claude.com` that no rule decided: at the domain, `api.anthropic.com`,
    `claude.ai`, `console.anthropic.com` and `statsig.anthropic.com` are
    FREE, any other host ASK (`NeverAuto`). For a request, see
    [Claude API](#claude-api).
13. **`CONNECT` defaults.** A trusted host: FREE. Any other: ASK,
    `NeverAuto`, red ("opens host for reads AND writes").
14. **Request defaults**, by class:

    | Class | When | Verdict |
    |---|---|---|
    | `receive-pack` | path ends `/git-receive-pack`, or query has `service=git-receive-pack` | ASK, red; the screen lists the refs pushed |
    | `websocket` | `Upgrade: websocket` | ASK ("the whole session is a write") |
    | `read` | `GET`, `HEAD`, `OPTIONS` with an empty body | FREE on a trusted host; else ASK (unknown host) |
    | `messaging` | a messaging host | ASK, red |
    | `publish` | a registry host and `PUT`, `PATCH`, `DELETE` (any write on an upload host) | ASK, red |
    | `upload` | body over 64 KiB or of unknown length, or a multipart, octet-stream, image, video, audio, zip or tar type | ASK |
    | `write` | anything else | ASK |

    Every default ASK is `NeverAuto`. A non-read body larger than
    `buffer_limit` is DENY `E_BODY_TOO_LARGE`.
15. **Heuristics.** With `heuristics = "enforce"`, a score of 3 or more
    turns any verdict but DENY into ASK, `NeverAuto`, red, with the reasons
    as warnings. With `"shadow"`, the reasons are only logged.
16. **Shadow mode.** With `mode = "shadow"`, see below.

### After the decision

17. A FREE request whose body exceeds `buffer_limit` is streamed only if a
    policy rule decided it; otherwise DENY `E_BODY_TOO_LARGE`. An ASK
    request whose body exceeds `buffer_limit` cannot be held: DENY
    `E_BODY_TOO_LARGE`.
18. A FREE request goes out (through `--upstream`, or dialled directly,
    refusing non-public addresses except for internal hosts). The `Host`
    sent upstream is the host decided, never the client's.
19. An ASK request waits in the gate's queue. No console: `E_NO_CONSOLE` at
    once. Past `hold`: `E_PENDING` (the item stays on the console). The
    human's `n` or the console's timeout: `E_DENIED` or `E_TIMEOUT`.

With no policy received yet (the console never answered since the gate
started), step 7 to 9 and 11 do nothing, nothing is trusted, and only the
four Claude hosts and their allowlist are free.

## Claude API

Once decrypted, a request to `api.anthropic.com`, `claude.ai`,
`console.anthropic.com` or `statsig.anthropic.com` that no rule decided:

1. **Credential.** Every value of `Authorization` (with or without
   `Bearer `) and `X-Api-Key` counts. Two or more: DENY `E_SECRET_EGRESS`.
   One whose sha256 is not in the caller's list of `credentials.json` (or
   keyproxy's list for a keyproxy request): DENY `E_SECRET_EGRESS`. With no
   `--credentials`, this check is off; with an unreadable file, every
   credential is refused.
2. **OAuth** (`/v1/oauth/` on the three hosts; `/oauth/` on `claude.ai`):
   FREE.
3. **`POST /v1/messages`, `POST /v1/messages/count_tokens`** on
   `api.anthropic.com`: FREE only if the body was held, is one JSON object
   with no duplicate key and no key equal to `mcp_servers`, `tools` or
   `container` but for case, and has no `mcp_servers`, no `container`, and
   no tool whose `type` is other than empty, `custom`, or `web_search`,
   `bash`, `text_editor`, `computer`, `memory` (with or without a
   `_YYYYMMDD` version suffix). Otherwise ASK, red, `NeverAuto`, with what
   was found.
4. **`/v1/files*`** on `api.anthropic.com`: ASK, `NeverAuto` (red unless a
   `GET`).
5. Other reads: FREE. Other writes: ASK, `NeverAuto`.

Rules come before this step: a rule for one of these hosts overrides the
allowlist (a `host = "*"` rule included).

## Exfiltration heuristics

Computed for requests (not at the domain) unless `heuristics = "off"`;
threshold 3.

| Signal | Points |
|---|---|
| more than 6 labels in the host name | 2 |
| a host label over 40 characters, or of 20+ characters with entropy above 3.8 | 2 each |
| a query string over 512 bytes | 2 |
| more than 20 query parameters | 1 |
| a query value over 128 bytes, or of 32+ characters with high entropy or long base64/hex (not a digest or version) | 2 each |
| a high-entropy path segment | 1 |
| an `X-*` header (but `X-Amz-*`, `X-Api-Key`, `X-Request-Id`) over 256 bytes or high-entropy | 2 each |
| a `User-Agent` over 256 bytes | 2 |
| an email address, IBAN or card number in the URL | 2 |

Query parameters that carry signatures or tokens by design (presigned URL
and OAuth parameters such as `X-Amz-Signature`, `sig`, `code`, `state`,
`token`) are not scored.

## Shadow mode

With `mode = "shadow"`, step 16 turns every ASK or DENY from steps 7-15
into FREE, and records what would have happened: the audit's `decision` is
`shadow-ask` or `shadow-deny`, and `shadow` holds the verdict. What stays
enforced:

- the floor (step 3) and the gate's own checks (steps 1, 2, 5, 17);
- secret matches and Claude credential mismatches (`E_SECRET_EGRESS`);
- the deny list (`E_RULE`), at the domain and inside a decrypted tunnel.

Everything else passes, including the Claude API allowlist, messaging,
publishing and git pushes. Use it to measure what a policy would ask before
you enforce it; `lockhttp doctor` warns while it is on.

`heuristics = "shadow"` (the default) is independent: the score is
computed and logged (`shadow_score` in the audit) but changes no verdict.

## Changing the policy: what counts as a loosening

The console compares the file with the approved policy every 2 s. A change
that only tightens is applied at once. A change that loosens waits, as a
whole, until you confirm it with `:review` (a tightening made in the same
edit waits with it); meanwhile the last approved policy stays in force. A
file that does not parse is reported, and the approved policy stays in
force.

| Change | Loosens when |
|---|---|
| `production` | `true` → `false` |
| `mode` | → `shadow` |
| `heuristics` | lowered (`enforce` → `shadow` → `off`) |
| `buffer_limit` | raised |
| `hold` | never |
| `connect_grant`, `idle_timeout`, `max_session` | raised |
| `trusted`, `splice`, `redirect_cdn` | an entry added |
| `deny` | an entry removed |
| `internal_hosts` | a host or port added, or `read` set (removing `read` tightens) |
| a rule added | unless its verdict is `deny` |
| a rule removed | unless its verdict is `free` (its requests fall back to another rule or the defaults) |
| a rule changed | its verdict rises (`deny` < `ask` < `auto` < `free`); or it now matches something it did not (another host, a container scope removed or changed, methods added or emptied, a wider path, a larger `max_body`, a later or removed `expires`); or a `deny`, `ask` or `auto` rule now matches less (what it no longer matches falls back elsewhere) |

The comparison is conservative: a rule's host change, for example, counts
as a loosening even toward a narrower host. `note` changes are not
compared.

## Examples

Trusted reads of docs, and their subdomains:

```toml
trusted = ["docs.rs", "readthedocs.io", "*.readthedocs.io"]
```

A container-scoped rule auto mode may answer (container names come from
lea's `sources.json`):

```toml
[[profiles.default.rules]]
id        = "search-api"
container = "lea-ab12cd34ef"
host      = "search.example.com"
methods   = ["POST"]
path      = "/v1/query"
verdict   = "auto"
max_body  = "16KiB"
expires   = "2026-12-31"
```

Rules come before the trusted list: a rule without `methods` on a trusted
host decides its reads too. List the methods you mean.

An API write path that always asks, even on a trusted host, while the rest
of the host follows the defaults:

```toml
[[profiles.default.rules]]
id      = "gh-issues"
host    = "api.github.com"
methods = ["POST", "PATCH"]
path    = "/repos/acme/shop/issues*"
verdict = "ask"
note    = "issue comments: always shown"
```

Deny a host for every container, except one:

```toml
[[profiles.default.rules]]
id      = "no-uploads-host"
host    = "transfer.example"
verdict = "deny"

[[profiles.default.rules]]
id        = "uploads-for-ci"
container = "lea-ci0000000"
host      = "transfer.example"
verdict   = "ask"
```

A pinned client: decide the host at the domain even when decrypting:

```toml
splice = ["updates.pinned-vendor.example"]
```

An internal service on a private address, reads free, writes asked:

```toml
[[profiles.default.internal_hosts]]
host  = "nexus.corp.example"
ports = [8081]
read  = true
```

A trial run before enforcing:

```toml
mode       = "shadow"
heuristics = "shadow"
```
