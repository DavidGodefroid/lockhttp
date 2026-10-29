# Using LockHTTP

This page lists every `lockhttp` command and flag, as the code defines
them. For the policy file, see [policy.md](policy.md); for the lea
integration, [lea.md](lea.md); for the image, its accounts and volumes,
[docker.md](docker.md).

```
lockhttp <command> [arguments]
```

lockhttp runs in Docker. On the host, `lockhttp` is the launcher
([`scripts/lockhttp`](../scripts/lockhttp)): it runs each command in the
image, as the account it needs ([docker.md](docker.md#subcommand--docker-run)).

| Command | Runs as | Volumes |
|---|---|---|
| `console` | the console account `lockhttp` (uid 10021), in the container `lockhttp-console`, no log driver | `lockhttp-run`, `lockhttp-home` |
| `init`, `policy` | `lockhttp` | `lockhttp-home` |
| `doctor` | `lockhttp` | `lockhttp-home` |
| `gate` | `gate` (uid 10003, in `lockhttp-clients`), in the container `lockhttp-gate`, port published on `127.0.0.1:3130` | `lockhttp-run` |
| `signer` | `signer` (uid 10004) | `lockhttp-signer` |
| `ca init` | you (your uid and gid) | the `--dir` directory, at its own path |
| `version`, `help` | `gate` (the image's default) | none |
| `update` | the launcher itself, on the host | |

lea does not use the launcher for the gate and the signer: it runs them
from the same image beside its proxy container ([lea.md](lea.md)). A path
given to a command is a path inside its container: only `ca init` mounts a
host directory; `LOCKHTTP_DOCKER_ARGS` adds mounts for the others.

Flags use Go's syntax: `-flag value`, `--flag value` or `--flag=value`.
Positional arguments are refused.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | failed |
| 2 | reserved ("no console" in the other Lock family tools; not used) |
| 3 | usage or configuration error |

## `lockhttp install`, `lockhttp setup`

Refused (exit 3): lockhttp runs in Docker and there is nothing to install
on the host. Install the launcher with `scripts/install.sh`
([docker.md](docker.md#install-and-update)); a former host install is
removed as in [Migrating from a host install](docker.md#migrating-from-a-host-install).

## `lockhttp init`

```
lockhttp init [--profile P] [--config FILE] [--trusted "a.com .corp.example"] [--force]
```

Writes the policy file, as the console account, in its home volume
(`lockhttp-home`).

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
It then prints `next: lockhttp console --profile P`.

## `lockhttp policy`

```
lockhttp policy show | edit | path [--config FILE]
```

The console account's policy file, in its home volume. The subcommand comes
first, then the flag.

| Subcommand | Effect |
|---|---|
| `show` | Prints the file. |
| `edit` | Opens the file in `$EDITOR` (`vi` when unset) in the container, then parses every profile in it. A file that does not parse exits 3, and the console keeps the approved policy until it does; otherwise it prints `saved: the console shows any loosening for approval (:review)`. |
| `path` | Prints the file's path (`/home/lockhttp/.config/lockhttp/config.toml` in the image). |

| Flag | Default | Meaning |
|---|---|---|
| `--config FILE` | `~/.config/lockhttp/config.toml` | The policy file. |

`show` and `edit` exit 1 when the file does not exist (`create it with:
lockhttp init`).

## `lockhttp console`

```
lockhttp console [--profile P] [--config FILE] [--auto]
```

The approval console: lockkit's console, serving `http.approve` and
`policy.get` to the gate. It must run in a terminal (exit 3 otherwise), as
the console account: the launcher runs it in the container
`lockhttp-console`, the only one that mounts `lockhttp-home`.

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

It checks the separated setup (the image's `/etc/lockhttp/system.toml`, and
`allowed_uids` when set), the policy (parse, mode, heuristics, counts; a
warning in shadow mode), the CA and the gate. The launcher runs it as the
console account, which alone can read the policy.

It runs in a container of its own: `--ca-cert` names a file inside it, and
`127.0.0.1` is that container. Mount the CA and join the gate's network
namespace with `LOCKHTTP_DOCKER_ARGS`, for example
`LOCKHTTP_DOCKER_ARGS="--network container:lockhttp-gate -v $PWD/ca.pem:/tmp/ca.pem:ro" lockhttp doctor --gate 127.0.0.1:3130 --ca-cert /tmp/ca.pem`.

## `lockhttp ca init`

```
lockhttp ca init --dir DIR [--name NAME] [--force]
```

Creates the local CA for decryption. The launcher creates `DIR` on the host
(`mkdir -p`), mounts it at its own path and runs the command as you, so the
files are yours.

| Flag | Default | Meaning |
|---|---|---|
| `--dir DIR` | required | Directory (created `0700`) for `ca.pem` (`0644`) and `ca-key.pem` (`0600`). |
| `--name NAME` | the host name | Installation name in the CA's subject. Through the launcher the host name is the container's: pass `--name`. |
| `--force` | off | Replace an existing CA (rotation). Without it, an existing `ca-key.pem` is refused. |

The CA is ECDSA P-256, `pathlen:0`, valid 90 days. Trust `ca.pem` in the
agents' containers only; give `ca-key.pem` to the signer only.

## `lockhttp gate`

```
lockhttp gate --listen ADDR [--upstream URL] [--profile P] [--sources FILE]
              [--credentials FILE] [--audit-dir DIR] [--status-file FILE]
              [--ca-cert FILE --signer SOCKET]
              [--hub URL --hub-key-file FILE --instance NAME [--home DIR]
               [--hub-net CIDR ...]] [--check]
```

The HTTP(S) proxy. It refuses to run as root; in the image it runs as
`gate` (uid 10003). Each flag but `--check` has an environment variable,
read when the flag is not given.

Through the launcher, `lockhttp gate` runs in the container `lockhttp-gate`
with the socket volume, publishes its port on `LOCKHTTP_PUBLISH`
(`127.0.0.1:3130` by default), and listens on `0.0.0.0:3130` unless you pass
`--listen`. lea runs its own gate ([lea.md](lea.md#2-the-gate-container)).

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
| `--hub URL` | `LOCKHTTP_HUB` | none | Hub mode: ask lockhub at this URL instead of the console. `--hub`, `--hub-key-file` and `--instance` go together. |
| `--hub-key-file FILE` | `LOCKHTTP_HUB_KEY_FILE` | none | The pinned public key of the hub (Ed25519, base64 on one line). Decisions verify under it only. |
| `--instance NAME` | `LOCKHTTP_INSTANCE` | none | The lock instance name the hub knows the gate by. |
| `--home DIR` | `LOCKHTTP_HOME` | the home directory | The gate's own volume (`0700`, the gate's uid only): the instance key (`hub/NAME.key`, made by `lockhttp hub-key`), the plans and the hub state (`hub/NAME/`). Never mount it in another container. |
| `--hub-net CIDR` | | none | A network of the hub. The gate refuses as a target the hub's host name, its addresses (resolved at start) and any name resolving into these networks, even when `internal_hosts` allows private addresses; a name that does not resolve is refused too. Repeatable. |
| `--check` | | off | Exit 0 if something answers on `--listen` (3 s), else 1. Starts nothing. |

**Hub mode.** An ask becomes a plan in the gate's volume and a ticket signed
with the instance key, pushed to the hub with the screen masked (personal
data and credentials). The request answers `E_PENDING` after `hold`, as
with a console. A decision that verifies under the pinned hub key, for this
instance and this request's fingerprint, under the policy in force, grants
the single-use authorisation (10 minutes) or, for a `CONNECT`, the connect
grant; its nonce is consumed once. A denial answers `E_DENIED` to a waiting
request. The risk class is `read` for `GET`/`HEAD` without a body, `write`
otherwise, `prod-write` under a production policy. The console still serves
the policy; it is not asked. Hub decisions are audited (`approved`/`denied`,
`approval` `hub`, `ticket`). An unreachable hub leaves the ask pending:
nothing falls back to the console.

The gate finds the console's socket as a lockkit client, in the socket
directory of the image's `/etc/lockhttp/system.toml`: `/run/lockhttp`, the
volume `lockhttp-run` it shares with the console.
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
(capped at the CA's expiry) to the gate over a Unix socket. In the image it
runs as `signer` (uid 10004). The launcher mounts nothing for it: lea runs
it with the key and a socket directory shared with the gate
([lea.md](lea.md#3-mitm-phase-2-optional)).

| Flag | Default | Meaning |
|---|---|---|
| `--ca-cert FILE` | required | CA certificate. |
| `--ca-key FILE` | required | CA key. Refused if readable by group or others (`chmod 0600`). |
| `--listen SOCKET` | required | Unix socket path (replaced if present, mode `0660`). |
| `--allow-uid N` | the signer's own uid | uid allowed to ask for leaves, checked with the kernel's peer credentials. Repeatable. |

It warns when the CA expires within 7 days. It issues leaves only for a
valid host name (no wildcard, no IP literal).

## `lockhttp hub-key`

```
lockhttp hub-key --instance NAME [--home DIR]
```

Prints the gate's instance public key (Ed25519, base64 on one line) for
`lock up` to pin at the hub. The first call makes the key in
`DIR/hub/NAME.key` (`0600`); `--home` defaults to `LOCKHTTP_HOME`, then the
home directory.

## `lockhttp version`, `lockhttp help`

`lockhttp version` (or `--version`) prints the launcher's version and the
image it runs (`lockhttp launcher X (image I)`), then the image's
`lockhttp vX`; `lockhttp help` (`-h`, `--help`) prints the usage. `lockhttp`
without a command prints the usage on stderr and exits 3.

## `lockhttp update`

```
lockhttp update [vX.Y.Z]
```

A launcher command, run on the host: replaces the launcher with a release's
(latest by default) after checking the cosign signature of `checksums.txt`,
the archive's checksum and the image's signature, then `docker pull`s the
pinned image ([docker.md](docker.md#install-and-update)).

## Files

| File | Where | Owner | Content |
|---|---|---|---|
| `/usr/local/bin/lockhttp` | host | root | the launcher |
| `/usr/local/bin/lockhttp` | image | root | the binary, the image's entrypoint |
| `/etc/lockhttp/system.toml` | image | root, `0644` | separated setup: console account, clients group, socket directory, `allowed_uids` (build arg `ALLOWED_UIDS`) |
| `/run/lockhttp/` | volume `lockhttp-run` | `lockhttp:lockhttp-clients`, `2710` | the console's sockets, `user-<profile>.sock` |
| `~/.config/lockhttp/config.toml` | volume `lockhttp-home` | `lockhttp`, `0600` | the policy |
| `~/.local/state/lockhttp/audit.log` | volume `lockhttp-home` | `lockhttp` | the console's audit (approvals, policy reviews) |
| `--audit-dir/gate-YYYY-MM-DD.jsonl` | the gate's container (lea: a host directory) | the gate's uid | the gate's audit |
| `ca.pem`, `ca-key.pem` | the `ca init --dir` directory | you; lea gives the key to the signer's uid | the local CA |

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
