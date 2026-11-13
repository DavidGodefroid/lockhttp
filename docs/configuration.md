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

## Managed configuration

A company can bound lockhttp on a machine with the Lock Family's managed
file: `/etc/lockfamily/managed.toml` on Linux,
`/Library/Application Support/lockfamily/managed.toml` on macOS, owned by
root and writable by root only, optionally signed. Its schema, signing and
deployment are in lockfamily's
[docs/managed.md](https://github.com/DavidGodefroid/lockfamily/blob/main/docs/managed.md).
lockhttp reads its `[lockhttp]` section. A user may tighten what it allows,
never loosen it:

```
hard-coded floor > managed bounds, rules and profiles > the policy file > managed defaults > built-in defaults
```

```toml
version = 1
organisation = "Example Corp"

[lockhttp.bounds]
mode          = "enforce"
connect_grant = "10m"
trusted       = ["*.example.com", "go.dev"]
deny          = ["pastebin.com"]

[[lockhttp.bounds.rules]]
id      = "no-paste"
host    = "*.paste.example.org"
verdict = "deny"

[lockhttp.defaults]
heuristics = "enforce"

[lockhttp.profiles.corp]
trusted = ["api.example.com"]
deny    = ["pastebin.com"]
```

- **`[lockhttp.profiles.<name>]`** has the keys of a `[profiles.<name>]`
  table. The console serves it as the company wrote it. A profile of the
  same name in the policy file is refused, naming it: rename yours.
- **`[lockhttp.defaults]`** takes the scalar keys `mode`, `heuristics`,
  `buffer_limit`, `hold`, `connect_grant`, `idle_timeout`, `max_session` and
  `production`. Each fills a profile that leaves the key unset; a value in
  the policy file wins. A default beyond the bounds is refused.
- **`[lockhttp.bounds]`** is a ceiling. The console checks the policy
  against it at start and at every poll: a policy beyond it is refused with
  one `blocked by company policy: …` line per key, never asked about and
  never approvable (audited `refused-managed`). A duration or a size beyond
  its bound is refused, never clamped. A managed profile beyond the bounds
  is an error in the managed file.

| Bound key | Value | The profile goes beyond it when |
|---|---|---|
| `production` | `true` only | it is not a production profile |
| `mode` | `"enforce"` only | it is in `shadow` mode |
| `heuristics` | `"shadow"` or `"enforce"` | its heuristics are lower (`off` < `shadow` < `enforce`) |
| `buffer_limit` | a size | its limit is larger |
| `connect_grant`, `idle_timeout`, `max_session` | a duration | its value is longer |
| `trusted`, `splice`, `redirect_cdn` | allowed list | it has an entry outside the list (`api.example.com` is within `*.example.com`; both sides of an `origin>cdn` entry are checked) |
| `internal_hosts` | allowed list of `{ host, ports, read }` | it has a host, a port, or `read = true` the list does not allow |
| `deny` | required list | an entry of the list is missing from its `deny` |
| `[[lockhttp.bounds.rules]]` | managed rules | (see below) |

`hold` and `inject` cannot be bounded: either key in `[lockhttp.bounds]` is
refused. An empty allowed list (`splice = []`) allows no entry; a key left
out bounds nothing.

**Managed rules** (`[[lockhttp.bounds.rules]]`) have the keys of
`[[profiles.P.rules]]`, with the verdict `deny` or `ask` only. They are
part of the policy the console approves and serves (its `managed_rules`,
and so its fingerprint), and they are matched on top of every other rule:

- a managed `deny` is refused like the deny list: no rule, grant or shadow
  mode lifts it;
- a managed `ask` makes a request that would pass, or that `auto` mode
  could answer, wait for a human;
- a stricter decision stands (a user `deny`, the floor);
- at the domain (a CONNECT not decrypted), a managed rule with `methods` or
  a `path` asks, since the gate cannot see the requests the tunnel carries;
- removing or changing a managed rule is a loosening.

`lockhttp managed show` prints the file the machine has and lockhttp's
section of it; `lockhttp managed check [--profile P]` checks the console's
policy file against it as the console does (exit 3 and one line per
violation; `lox` runs it before it starts the lock); `lockhttp doctor`
names the managed file and checks the project's profiles against it. A
`[family] vault` setting has no effect on lockhttp, which holds no
database or broker credentials.
