# Using LockHTTP

This page lists every `lockhttp` command and flag of v0.1.0, as the code
defines them. For the policy file, see [policy.md](policy.md); for the lea
integration, [lea.md](lea.md).

```
lockhttp <command> [arguments]
```

| Where it runs | Commands |
|---|---|
| Host, as root (once) | `install` |
| Host, as the console account (`lockhttp`) | `init`, `console`, `doctor` |
| Host (lea) or anywhere the CA is kept | `ca init` |
| Proxy container (lea), or the host as another account than the console's | `gate`, `signer` |
| Anywhere | `version`, `help` |

Flags use Go's syntax: `-flag value`, `--flag value` or `--flag=value`.
Positional arguments are refused.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | failed |
| 2 | reserved ("no console" in the other Lock family tools; not used) |
| 3 | usage or configuration error |

## `lockhttp install`

```
lockhttp install [--client USER] [--gate-uid N [--rootless]] [--user lockhttp]
                 [--group lockhttp-clients] [--print] [--trust-binary] [--yes]
```

The one-time setup that separates the console from the agent. It prints the
shell script it will run as root, then asks `Run them now with sudo? [y/N]`.

| Flag | Default | Meaning |
|---|---|---|
| `--client USER` | `$SUDO_USER`, else the current user | The account the agents (lea) run as. It joins the clients group. Must differ from `--user`. |
| `--user NAME` | `lockhttp` | The console account to create. |
| `--group NAME` | `lockhttp-clients` | The group allowed to reach the console's socket directory. |
| `--gate-uid N` | none | The gate's uid inside lea's proxy container (lea uses `10003`). Written to `allowed_uids` in `/etc/lockhttp/system.toml`. `0` is refused. |
| `--rootless` | off | The proxy container runs under rootless Podman: `--gate-uid` is mapped through `/etc/subuid` for `--client` (uid `n` ≥ 1 becomes `subuid_start + n - 1`). Requires `--gate-uid`. |
| `--print` | off | Print the commands, do not run them. |
| `--trust-binary` | off | Copy this binary even when an account other than root could change it (its sha256 is checked again by the root script). Without it, such a binary is refused. |
| `--yes` | off | Run the commands without asking. Without a terminal, `--print` or `--yes` is required. |

On Linux the script creates the console account (home, `/bin/bash`), the
clients group with `--client` in it, `/etc/lockhttp/system.toml`, the
socket directory `/run/lockhttp` (`2710 lockhttp:lockhttp-clients`, through
`/etc/tmpfiles.d/lockhttp.conf`), and copies the binary to
`/usr/local/bin/lockhttp`, owned by root. On another OS the commands are
printed, to be run as an administrator.

Then:

1. `sudo passwd lockhttp`
2. log in as `lockhttp` in its own session (switch user), then
   `lockhttp init` and `lockhttp console`;
3. start the gate (lea does it with `LEA_LOCKHTTP=1`), then `lockhttp doctor`.

## `lockhttp init`

```
lockhttp init [--profile P] [--config FILE] [--trusted "a.com .corp.example"] [--force]
```

Writes the policy file, as the console account.

| Flag | Default | Meaning |
|---|---|---|
| `--profile P` | `default` | Profile name (the table `[profiles.P]`). |
| `--config FILE` | `~/.config/lockhttp/config.toml` | The policy file. |
| `--trusted "..."` | none | Hosts to trust for reads, space or comma separated, in the format of lea's `LEA_EGRESS_ALLOW`: `example.org` adds that host; `.corp.example` adds `corp.example` and `*.corp.example`. |
| `--force` | off | Overwrite an existing file. Without it, an existing file is left alone (exit 1). |

The file holds the profile with `mode = "enforce"`, `heuristics = "shadow"`,
`buffer_limit = "10MiB"`, `hold = "60s"`, `connect_grant = "10m"`, the
initial trusted set (Go, Python, npm, Node, MDN, Docker, Kubernetes, man7,
`docs.anthropic.com`, GitHub, crates.io, Debian, Ubuntu, Alpine) plus the
`--trusted` hosts, empty `splice` and `deny` lists, and a commented rule
example. It is written `0600` in a `0700` directory, after being parsed.

## `lockhttp console`

```
lockhttp console [--profile P] [--config FILE] [--auto]
```

The approval console: lockkit's console, serving `http.approve` and
`policy.get` to the gate. It must run in a terminal, as the console account,
in its own login session (lockkit's isolation checks refuse other shapes).

| Flag | Default | Meaning |
|---|---|---|
| `--profile P` | `default` | Profile to serve. Its socket is `user-P.sock` in the socket directory. |
| `--config FILE` | `~/.config/lockhttp/config.toml` | The policy file. |
| `--auto` | off | Start in auto mode. Only screens that match an approved `verdict = "auto"` rule are ever auto-approved; every other screen is still prompted. |

At the first start of a profile you review its whole policy (`Apply these
changes? [y/N]`); at a later start, a loosening made since the last
approval is shown for the same answer. The console reads the policy file
again every 2 s. It serves
the gate only the policy you approved: a change that loosens it waits until
you confirm it with `:review` (lockkit's "the AI tightens, the human
loosens" review).

In the console:

| Key or command | Effect |
|---|---|
| `y` | Approve the request on screen. |
| `n <reason>` | Deny it; the agent reads the reason. |
| Shift+Tab, `:mode` | Manual ⇄ auto mode. |
| `:review` | Review a pending policy change. |
| `:status` | The console's state. |
| `:quit` | Stop the console. |

An unanswered screen is denied after 5 minutes (lockkit's approval timeout).

What a `y` means:

| Screen | `y` |
|---|---|
| `OPEN host · container` (a `CONNECT` decided at the domain) | Opens container × host × port for `connect_grant`, for reads and writes. |
| `METHOD host · container` (a decrypted or plain HTTP request) | Lets that request through. If the client already left (the screen says "client gone"), the identical request may pass once in the next 10 minutes. |

The screen shows the container (and project), the declared agent and how it
was attributed, the method, host and path (the query string as its length
only), the body size, `Content-Type` and fingerprint, the request's header
names, lea's task metadata, the rule that decided, warnings in red, the refs
of a git push, a masked body preview (first 1 KiB of a textual body,
personal data and credentials masked), and the number of distinct requests
pending under the same container, method, host and path.

## `lockhttp doctor`

```
lockhttp doctor [--profile P] [--config FILE] [--ca-cert FILE] [--gate ADDR]
```

Checks the setup and prints one line per check. Exit 1 when a check fails.

| Flag | Default | Meaning |
|---|---|---|
| `--profile P` | `default` | Profile to check in the policy file. |
| `--config FILE` | `~/.config/lockhttp/config.toml` | The policy file. |
| `--ca-cert FILE` | none | CA certificate to check (fails under 7 days of validity). Without it, the doctor warns that decryption is off. |
| `--gate ADDR` | none | Gate address to dial (for example `127.0.0.1:3130`). |

It checks the separated setup (`/etc/lockhttp/system.toml`, `allowed_uids`),
whether the running binary is root-owned, the policy (parse, mode,
heuristics, counts; a warning in shadow mode), the CA and the gate. Run it
as the console account to check the policy, which other accounts cannot
read.

## `lockhttp ca init`

```
lockhttp ca init --dir DIR [--name NAME] [--force]
```

Creates the local CA for decryption.

| Flag | Default | Meaning |
|---|---|---|
| `--dir DIR` | required | Directory (created `0700`) for `ca.pem` (`0644`) and `ca-key.pem` (`0600`). |
| `--name NAME` | the host name | Installation name in the CA's subject. |
| `--force` | off | Replace an existing CA (rotation). Without it, an existing `ca-key.pem` is refused. |

The CA is ECDSA P-256, `pathlen:0`, valid 90 days. Trust `ca.pem` in the
agents' containers only; give `ca-key.pem` to the signer only.

## `lockhttp gate`

```
lockhttp gate --listen ADDR [--upstream URL] [--profile P] [--sources FILE]
              [--credentials FILE] [--audit-dir DIR] [--status-file FILE]
              [--ca-cert FILE --signer SOCKET] [--check]
```

The HTTP(S) proxy. It refuses to run as root (uid 0 in a rootless container
is the host user, which the console refuses as a client). Each flag but
`--check` has an environment variable, read when the flag is not given.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--listen ADDR` | `LOCKHTTP_LISTEN` | `127.0.0.1:3130` | Address to listen on. |
| `--upstream URL` | `LOCKHTTP_UPSTREAM` | none | Proxy to send through, `http://host:port` (lea: squid, `http://127.0.0.1:3128`). Empty: the gate dials targets itself and refuses non-public addresses (except internal hosts). |
| `--profile P` | `LOCKHTTP_PROFILE` | `default` | Console profile to dial. |
| `--sources FILE` | `LOCKHTTP_SOURCES` | none | `sources.json` written by lea. Empty: standalone, every connection is container `local`. An unreadable or invalid file at start is a configuration error; later, it refuses every connection until fixed. |
| `--credentials FILE` | `LOCKHTTP_CREDENTIALS` | none | `credentials.json` written by lea: hashes of each container's Claude credentials. Empty: the check is off. Unreadable or invalid: every credential is unknown (denied). |
| `--audit-dir DIR` | `LOCKHTTP_AUDIT_DIR` | none (stderr) | Directory (created `0700`) of the JSONL audit: `gate-YYYY-MM-DD.jsonl` (UTC), files `0600`, kept 30 days. |
| `--status-file FILE` | `LOCKHTTP_STATUS_FILE` | none | Status file for lea, rewritten atomically on change: `version`, `console` (`up`/`down`), `pending`, `pending_by_container`, `policy_fp`, `updated`. |
| `--ca-cert FILE` | `LOCKHTTP_CA_CERT` | none | CA certificate. Enables decryption, with `--signer`. |
| `--signer SOCKET` | `LOCKHTTP_SIGNER` | none | The signer's Unix socket. `--ca-cert` and `--signer` go together. |
| `--check` | | off | Exit 0 if something answers on `--listen` (3 s), else 1. Starts nothing. |

The gate finds the console's socket as a lockkit client: in the socket
directory of `/etc/lockhttp/system.toml` on a host with the separated setup,
else in `$LOCKHTTP_RUNTIME_DIR/lockhttp/` (lea sets
`LOCKHTTP_RUNTIME_DIR=/run` and bind-mounts the host's `/run/lockhttp`).
It polls the policy every 2 s and reloads `--sources` and `--credentials`
when they change.

Clients reach the gate as an HTTP proxy: `CONNECT host:port` for HTTPS,
absolute `http://` URLs for plain HTTP. `Proxy-Authorization: Basic`
carries the agent name and token (the token is matched in `sources.json`;
in standalone mode the name is recorded as given).

On stderr the gate logs its start (`listening on ..., profile ..., domain
(CONNECT + SNI)` or `decrypting (signer ...)`), the console going up or
down, and policy changes (by fingerprint).

## `lockhttp signer`

```
lockhttp signer --ca-cert FILE --ca-key FILE --listen SOCKET [--allow-uid N ...]
```

The only process that reads the CA key. It issues 24-hour leaf certificates
(capped at the CA's expiry) to the gate over a Unix socket.

| Flag | Default | Meaning |
|---|---|---|
| `--ca-cert FILE` | required | CA certificate. |
| `--ca-key FILE` | required | CA key. Refused if readable by group or others (`chmod 0600`). |
| `--listen SOCKET` | required | Unix socket path (replaced if present, mode `0660`). |
| `--allow-uid N` | the signer's own uid | uid allowed to ask for leaves, checked with the kernel's peer credentials. Repeatable. |

It warns when the CA expires within 7 days. It issues leaves only for a
valid host name (no wildcard, no IP literal).

## `lockhttp version`, `lockhttp help`

`lockhttp version` (or `--version`) prints the version; `lockhttp help`
(`-h`, `--help`) prints the usage. `lockhttp` without a command prints the
usage on stderr and exits 3.

## Files

| File | Owner | Content |
|---|---|---|
| `/usr/local/bin/lockhttp` | root | the binary the console account runs |
| `/etc/lockhttp/system.toml` | root, `0644` | separated setup: console account, clients group, socket directory, `allowed_uids` |
| `/run/lockhttp/` | `lockhttp:lockhttp-clients`, `2710` | the console's sockets, `user-<profile>.sock` |
| `~lockhttp/.config/lockhttp/config.toml` | `lockhttp`, `0600` | the policy |
| `~lockhttp/.local/state/lockhttp/audit.log` | `lockhttp` | the console's audit (approvals, policy reviews) |
| `--audit-dir/gate-YYYY-MM-DD.jsonl` | the gate's uid | the gate's audit |
| `ca.pem`, `ca-key.pem` | the signer's uid for the key | the local CA |

## Audit records

Both audits write one JSON object per line with lockkit's base fields
(`event`, `decision`, `code`, `reason`, `warnings`, `approval`, `profile`,
...) and lockhttp's: `request_id`, `container`, `project`, `via`, `agent`,
`attribution`, `role`, `parent`, `task_id`, `branch`, `session_id`,
`phase`, `tls` (`connect`, `mitm`, `plain`), `method`, `host`, `port`,
`path`, `query_len`, `query_hash`, `req_headers` (names only), `req_bytes`,
`body_fp`, `rule`, `class`, `score`, `shadow_score`, `shadow`, `status`,
`resp_bytes`, `duration_ms`, `policy_fp`. Never a body, a query string or a
header value.

`decision` is `free`, `approved`, `refused`, or `shadow-ask` /
`shadow-deny` for what shadow mode let through.
