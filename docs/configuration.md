# Configuring lockhttp

The policy file, every profile key, and examples. The full reference, with the evaluation order, is [policy.md](policy.md).

> Moved from the README, whole. `lox run` runs the hub and the lockhttp
> console, writes `.lockfamily/up.json` and serves the decisions in its
> terminal; it replaces lockhub's deprecated `lox up`.

## Configuration

The policy lives in the console account's `~/.config/lockhttp/config.toml`,
one table per profile. The console reads it, reloads it when it changes,
and holds every change that loosens it until you confirm it with `:review`.
Unknown keys and keys that look like secrets are refused.

```toml
[profiles.default]
mode          = "enforce"   # enforce | shadow
heuristics    = "shadow"    # off | shadow | enforce
buffer_limit  = "10MiB"     # largest body held for a human
hold          = "60s"       # how long a request waits for the human (max 5m)
connect_grant = "10m"       # how long an approved CONNECT opens its host
trusted = ["go.dev", "pkg.go.dev", "github.com", "api.github.com"]
splice  = []                # never decrypted (certificate pinning)
deny    = []                # always refused
```

<details>
<summary>All profile keys</summary>

| Key | Default | Notes |
|---|---|---|
| `production` | `false` | No rule may be `auto` (an `auto` rule only asks), and the console treats the profile as production. |
| `mode` | `enforce` | `shadow`: what would ask or be denied passes and is logged as such. |
| `heuristics` | `shadow` | Exfiltration score: `off` (not computed), `shadow` (logged), `enforce` (a score ≥ 3 asks, `NeverAuto`, red). |
| `buffer_limit` | `10MiB` | `B`, `KiB`, `MiB`, `GiB` or bytes; more than 0. |
| `hold` | `60s` | Go duration, at least `1s`, at most `5m`. |
| `connect_grant` | `10m` | At least `1s`. |
| `idle_timeout` | `24h` | Console session limit. |
| `max_session` | `24h` | Console session limit. |
| `trusted` | `[]` (`init` writes a docs set) | Reads (`GET`, `HEAD`, `OPTIONS` without body) are free. |
| `splice` | `[]` | Never decrypted: decided at the domain. |
| `deny` | `[]` | Always refused (`E_RULE`). |
| `redirect_cdn` | `[]` | `"origin>cdn"`: a 3xx from origin to cdn lets the same container `GET` that exact URL once within 60 s. Eight GitHub, Docker, Go and PyPI pairs are built in. |
| `[[profiles.P.internal_hosts]]` | none | `host`, `ports` (required), `read` (`false`). May resolve to a private address. |
| `[[profiles.P.rules]]` | none | `id`, `container`, `host`, `methods`, `path`, `verdict`, `max_body`, `expires`, `note`. |

</details>

Hosts are names: `example.com`, or `*.example.com` for its subdomains (not
`example.com` itself). IP literals are refused. The full reference, with
the evaluation order and what counts as a loosening, is in
[docs/policy.md](policy.md).

### Policy examples

```toml
[profiles.default]
trusted = ["docs.rs", "*.readthedocs.io"]       # free reads of docs
splice  = ["pinned.example.com"]                # a client that pins its certificate
deny    = ["pastebin.com"]

# A container-scoped rule: the gate asks lockhub and a human answers
[[profiles.default.rules]]
id        = "npm-audit"
container = "lea-ab12cd34ef"
host      = "registry.npmjs.org"
methods   = ["POST"]
path      = "/-/npm/v1/security/advisories/bulk"
verdict   = "ask"
expires   = "2026-12-31"

# Every write under an API path asks (NeverAuto), even on a trusted host
[[profiles.default.rules]]
id      = "issues-write"
host    = "api.github.com"
methods = ["POST", "PATCH"]
path    = "/repos/acme/shop/issues*"
verdict = "ask"

# Refuse a host for every container
[[profiles.default.rules]]
id      = "no-gists"
host    = "gist.github.com"
verdict = "deny"

# An internal host on a private address: free reads on 8443
[[profiles.default.internal_hosts]]
host  = "git.corp.example"
ports = [8443]
read  = true
```

To try a policy before enforcing it, set `mode = "shadow"`: what would ask
or be denied passes and is audited with `"decision": "shadow-ask"` or
`"shadow-deny"`. The floor and secret matches stay enforced.
