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
| `profile add`, `init`, `doctor` | you (your uid and gid), from the current directory | the project, at its own path |
| `policy` | `lockhttp` | `lockhttp-home` |
| `gate` | `gate` (uid 10003, in `lockhttp-clients`), in the container `lockhttp-gate`, port published on `127.0.0.1:3130` | `lockhttp-run` |
| `signer` | `signer` (uid 10004) | `lockhttp-signer` |
| `ca init` | you (your uid and gid) | the `--dir` directory, at its own path |
| `version`, `help` | `gate` (the image's default) | none |
| `update` | the launcher itself, on the host | |

lea does not use the launcher for the gate and the signer: it runs them
from the same image beside its proxy container ([lea.md](lea.md)). A path
given to a command is a path inside its container: only `ca init` and the
launcher verbs (the project) mount a host directory; `LOCKHTTP_DOCKER_ARGS`
adds mounts for the others.

Flags use Go's syntax: `-flag value`, `--flag value` or `--flag=value`.
Positional arguments are refused.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | failed |
| 2 | reserved ("no console" in the other Lock family tools; not used) |
| 3 | usage or configuration error |

## Launcher verbs

`lox add` sets up every lock of a project through the same three verbs
(lockkit's GUIDE.md, "Launcher verbs"):

```
lockhttp profile add --non-interactive --json --profile NAME [--production]
lockhttp init claude
lockhttp doctor --fix --yes --json
```

The launcher runs them as you, with the project mounted at its own path
and the current directory as the working directory. The project is the
nearest directory holding `.lockhttp/config.toml`, else the nearest holding
`.git`, else the current directory. With `--json`, a verb prints exactly
one line of JSON on stdout, even when it fails: lockkit's `verbs.Profile`,
`verbs.Doctor` or `verbs.Error` (`{"lock":"lockhttp","code":"usage|secret|exists|failed","error":"..."}`);
human text goes to stderr.

### `lockhttp profile add`

```
lockhttp profile add [--non-interactive] [--json] [--project DIR] [--profile NAME]
                     [--production] [--trusted "a.com .corp.example"]
```

Adds one profile, with the default policy, to the project's
`.lockhttp/config.toml`, which `lox run` reviews and copies into the
lockhttp console. A new file is written `0600` in a `0700` directory; a
profile added to an existing file is appended, the other profiles left
byte for byte. A profile already in the file is never rewritten: exit 1,
code `exists`, nothing written.

| Flag | Default | Meaning |
|---|---|---|
| `--non-interactive` | off | Never read the terminal. Without it, `profile add` asks on the terminal for what the flags did not give (name, production, trusted hosts), and refuses without a terminal (exit 3). |
| `--json` | off | One line of JSON on stdout: `{"lock":"lockhttp","profile":"web","config":"/path/.lockhttp/config.toml","production":false}`, or a `verbs.Error`. |
| `--project DIR` | the project of the current directory | The project (the launcher mounts it). |
| `--profile NAME` | `default` | Profile name (the table `[profiles.NAME]`). |
| `--production` | off | A production profile (`production = true`): its name is typed for every approval, so it needs 2 characters or more and not `y`, `yes`, `n`, `no` or `ok`. |
| `--trusted "..."` | none | Hosts to trust for reads (the config key `trusted`), space or comma separated, in the format of lea's `LEA_EGRESS_ALLOW`: `example.org` adds that host; `.corp.example` adds `corp.example` and `*.corp.example`. |

lockhttp's target needs no secret: `profile add` takes no `--credentials`,
and its JSON has no `credentials` key. No form of it takes, asks for or
writes a secret: a flag named like one (`--password`, `--token`, ...), a
value that embeds a password (`user:pw@host`, `password=`) or a positional
argument is refused (code `secret`, or `usage` for a positional argument)
before anything is written, and no error quotes a flag's value.

The profile holds `mode = "enforce"`, `heuristics = "shadow"`,
`buffer_limit = "10MiB"`, `hold = "60s"`, `connect_grant = "10m"`, the
initial trusted set (Go, Python, npm, Node, MDN, Docker, Kubernetes, man7,
`docs.anthropic.com`, GitHub, crates.io, Debian, Ubuntu, Alpine) plus the
`--trusted` hosts, empty `splice` and `deny` lists, and a commented rule
example. The file is parsed before it is written.

### `lockhttp init`

```
lockhttp init <agent>
```

`<agent>` is one of `claude`, `codex`, `cursor`, `gemini`. lockhttp has no
agent files: lea routes the agent's HTTP through the gate. `init` checks
the agent, writes nothing, says so and exits 0. It takes no flag.

## `lockhttp policy`

```
lockhttp policy show | edit | path [--config FILE]
```

The console account's policy file, in its home volume. The subcommand comes
first, then the flag.

| Subcommand | Effect |
|---|---|
| `show` | Prints the file, then one `# profile <name> (managed)` comment line per profile of the company's managed configuration. |
| `edit` | Opens the file in `$EDITOR` (`vi` when unset) in the container, then parses every profile in it. A file that does not parse exits 3, and the console keeps the approved policy until it does; otherwise it prints `saved: the console shows any loosening for approval (:review)`. |
| `path` | Prints the file's path (`/home/lockhttp/.config/lockhttp/config.toml` in the image). |

| Flag | Default | Meaning |
|---|---|---|
| `--config FILE` | `~/.config/lockhttp/config.toml` | The policy file. |

`show` and `edit` exit 1 when the file does not exist: `lockhttp profile
add` writes the policy in the project, and `lox run` copies it into the
console.

## `lockhttp console`

```
lockhttp console [--profile P] [--config FILE]
```

The policy console: lockkit's console, serving `policy.get` to the gate.
It asks no question about a request: the gate asks lockhub about every held
request, and you answer on a facade of the hub (`lox approve`, lea's deck,
a paired phone). It must run in a terminal (exit 3 otherwise), as the
console account. Under `lox run` it runs in its own compose service, with
the policy copied from `<workspace>/.lockhttp/` (`lox attach <instance>`
attaches its terminal); the launcher runs it in the container
`lockhttp-console`, the only one that mounts `lockhttp-home`. It is
lockkit's policy-only console: it takes no hub flags (`lox run` passes
none to it, only to the gate) and approves no request; one that reached
it would be refused. The gate, not the console, needs the hub flags.

| Flag | Default | Meaning |
|---|---|---|
| `--profile P` | `default` | Profile to serve. Its socket is `user-P.sock` in the socket directory. |
| `--config FILE` | `~/.config/lockhttp/config.toml` | The policy file. |

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
| `:review` | Review a pending policy change. |
| `:status` | The console's state. |
| `:quit` | Stop the console. |

Under the company's managed configuration ([configuration.md](configuration.md#managed-configuration)),
the console prints `Managed by <organisation> (sha256:…)` at start and
checks the policy against `[lockhttp.bounds]`: a policy beyond it is
refused with one `blocked by company policy: …` line per key, without a
prompt, and the console exits 3; a change beyond it while the console runs
is refused at the next poll, never pending. A managed file that cannot be
read, is not root's or does not verify is a refusal to start (exit 3).

What an approval on the hub means:

| Request | Approved |
|---|---|
| A `CONNECT` decided at the domain | Opens container × host × port for `connect_grant`, for reads and writes. |
| A decrypted or plain HTTP request | Lets that request through. If the client already left (`E_PENDING`), the identical request may pass once in the next 10 minutes. |

The ticket's screen shows the container (and project), the declared agent
and how it was attributed, the method, host and path (the query string as
its length only), the body size, `Content-Type` and fingerprint, the
request's header names, lea's task metadata, the rule that decided,
warnings in red, the refs of a git push, a masked body preview (first 1 KiB
of a textual body, personal data and credentials masked), and the number of
distinct requests pending under the same container, method, host and path.

## `lockhttp managed`

```
lockhttp managed show
lockhttp managed check [--profile P] [--config FILE]
```

The company's managed configuration (`/etc/lockfamily/managed.toml`, see
[configuration.md](configuration.md#managed-configuration)), as the
console applies it. The launcher runs it as the console account, with its
home volume and the host's managed directory read-only on `/etc/lockfamily`
([docker.md](docker.md#the-companys-managed-configuration)).

| Subcommand | Effect |
|---|---|
| `show` | Prints the file's `path`, `organisation`, `fingerprint`, `signed` (`yes` or `no`) and lockhttp's `bounds`, `defaults` and `profiles`, managed rules included. |
| `check` | Loads the console's policy file as the console does and checks every profile, or the one named, against the bounds and the managed rules. It opens no connection. |

| Flag | Default | Meaning |
|---|---|---|
| `--profile P` | every profile | `check`: the profile to check. |
| `--config FILE` | `~/.config/lockhttp/config.toml` | `check`: the policy file. |

Output and exit codes are a contract (`lox` runs `managed check` before it
starts the lock):

| Case | `show` | `check` |
|---|---|---|
| No managed file | `no managed configuration`, exit 0 | `no managed configuration`, exit 0 |
| Within the bounds | the file, exit 0 | `profile P: within the company's managed configuration` per profile, exit 0 |
| Beyond the bounds | | one `blocked by company policy: <key> … (profile P: …)` line per violation on stdout, exit 3 |
| A refused file | the lockkit error on stderr, exit 3 | `blocked by company policy: <the lockkit error>`, exit 3 |

## `lockhttp doctor`

```
lockhttp doctor [--fix [--yes]] [--json] [--profile P] [--ca-cert FILE] [--gate ADDR]
```

A launcher verb: checks the setup and the project of the current directory
and prints one line per check (`✓`, `▲` warning, `✗` failure). Exit 0
exactly when no check fails (a warning does not fail), 1 otherwise.

| Flag | Default | Meaning |
|---|---|---|
| `--fix` | off | Repair what can be (the write permission others have on the project's policy or its `.lockhttp` directory), asking before each repair, then check again. Without a terminal it needs `--yes` (exit 3 otherwise). |
| `--yes` | off | With `--fix`: repair without asking. Alone, a usage error (exit 3). |
| `--json` | off | One line of JSON on stdout: `{"lock":"lockhttp","ok":true,"fixed":[],"checks":[{"check":"policy","status":"ok","detail":"...","fix":"..."}]}`; a usage error prints a `verbs.Error` instead (the `code` key rather than `checks`). |
| `--profile P` | every profile | Profile to check in the project's policy. |
| `--ca-cert FILE` | none | CA certificate to check (fails under 7 days of validity). Without it, the doctor warns that decryption is off. |
| `--gate ADDR` | none | Gate address to dial (for example `127.0.0.1:3130`). |

The checks: `setup`, the separated setup (the image's
`/etc/lockhttp/system.toml`, and `allowed_uids` when set); `agent`, nothing
to wire; `managed`, the company's managed configuration (`Managed by …
(sha256:…)`, `no managed configuration`, or a failure with the lockkit
error); `policy`, the project's `.lockhttp/config.toml` (missing: run
`lockhttp profile add`), each profile parsed as the console loads it, with
its mode, heuristics and counts, a warning in shadow mode, a failure with
the `blocked by company policy: …` lines when it goes beyond the managed
bounds; `permissions`, the policy and its
directory writable by their owner only (`--fix` removes the others' write
permission); `ca` and `gate`.

It runs in a container of its own: `--ca-cert` names a file inside it (a
file in the project is at its own path), and
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
lockhttp gate --listen ADDR --hub URL --hub-key-file FILE --instance NAME
              [--home DIR] [--hub-net CIDR ...] [--hub-plain-http]
              [--devices-file FILE [--require-device RISKS] [--seal-clear]]
              [--facade-keys-file FILE]
              [--upstream URL] [--profile P] [--sources FILE]
              [--credentials FILE] [--secrets FILE] [--audit-dir DIR] [--status-file FILE]
              [--ca-cert FILE --signer SOCKET]
lockhttp gate --check [--listen ADDR]
```

The HTTP(S) proxy. It runs hub-attached only: without `--hub`,
`--hub-key-file` and `--instance` it exits with a usage error (exit 3,
"launched by `lox run` only"); lea passes them from `lox run`'s `up.json`.
It refuses to run as root; in the image it runs as `gate` (uid 10003).
Each flag but `--check` has an environment variable, read when the flag is
not given.

Through the launcher, `lockhttp gate` runs in the container `lockhttp-gate`
with the socket volume, publishes its port on `LOCKHTTP_PUBLISH`
(`127.0.0.1:3130` by default), and listens on `0.0.0.0:3130` unless you pass
`--listen`. lea runs its own gate ([lea.md](lea.md#2-the-gate-container)).

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--listen ADDR` | `LOCKHTTP_LISTEN` | `127.0.0.1:3130` | Address to listen on. |
| `--upstream URL` | `LOCKHTTP_UPSTREAM` | none | Proxy to send through, `http://host:port` (lea: squid, `http://127.0.0.1:3128`). Empty: the gate dials targets itself and refuses non-public addresses (except internal hosts). |
| `--profile P` | `LOCKHTTP_PROFILE` | `default` | Console profile to dial. |
| `--sources FILE` | `LOCKHTTP_SOURCES` | none | `sources.json` written by lea. Empty: every connection is container `local`. An unreadable or invalid file at start is a configuration error; later, it refuses every connection until fixed. |
| `--credentials FILE` | `LOCKHTTP_CREDENTIALS` | none | `credentials.json` written by lea: hashes of each container's Claude credentials. Empty: the check is off. Unreadable or invalid: every credential is unknown (denied). |
| `--secrets FILE` | `LOCKHTTP_SECRETS` | none | The gate's secrets file: the values the policy's `inject` entries name ([policy.md](policy.md#credential-injection)). JSON `{"version": 1, "secrets": {"name": "value"}}`, mode `0600` (refused if group- or world-readable), in the gate's container only, never an agent's. Reloaded when it changes. Invalid at start: a configuration error; later, every injection is refused (`E_INJECT`). |
| `--audit-dir DIR` | `LOCKHTTP_AUDIT_DIR` | none (stderr) | Directory (created `0700`) of the JSONL audit: `gate-YYYY-MM-DD.jsonl` (UTC), files `0600`, kept 30 days. |
| `--status-file FILE` | `LOCKHTTP_STATUS_FILE` | none | Status file for lea, rewritten atomically on change: `version`, `console` (`up`/`down`), `pending`, `pending_by_container`, `policy_fp`, `updated`. |
| `--ca-cert FILE` | `LOCKHTTP_CA_CERT` | none | CA certificate. Enables decryption, with `--signer`. |
| `--signer SOCKET` | `LOCKHTTP_SIGNER` | none | The signer's Unix socket. `--ca-cert` and `--signer` go together. |
| `--hub URL` | `LOCKHTTP_HUB` | none (required) | The lockhub URL the gate asks. `--hub`, `--hub-key-file` and `--instance` are required together. |
| `--hub-key-file FILE` | `LOCKHTTP_HUB_KEY_FILE` | none (required) | The pinned public key of the hub (Ed25519, base64 on one line). Decisions verify under it only. |
| `--instance NAME` | `LOCKHTTP_INSTANCE` | none (required) | The lock instance name the hub knows the gate by. |
| `--home DIR` | `LOCKHTTP_HOME` | the home directory | The gate's own volume (`0700`, the gate's uid only): the instance key (`hub/NAME.key`, made by `lockhttp hub-key`), the plans and the hub state (`hub/NAME/`). Never mount it in another container. |
| `--hub-plain-http` | `LOCKHTTP_HUB_PLAIN_HTTP=1` | off | Allow an `http://` `--hub` URL to a hub on a network of its own: a service name without a dot (`lockhub`) or a private address only. Without it an `http://` hub is refused unless it is a loopback address; use `https`. Requests and decisions are signed either way. |
| `--facade-keys-file FILE` | `LOCKHTTP_FACADE_KEYS_FILE` | none | The facade keys the gate pins (JSON, written by `lox run`). A reveal (Ctrl-O on a local facade of the hub) is answered with the ticket's clear screen sealed to the facade's ephemeral key, only when one of these keys signed it; the hub relays ciphertext. Without it, reveals are refused. |
| `--devices-file FILE` | `LOCKHTTP_DEVICES_FILE` | none | The approval devices the gate pins (JSON, written by `lox run` at `/run/lockfamily/devices.json`). A decision taken on a device (the hub's mobile facade) is acted on only if it carries the signature of one of them over the gate's own signed ticket. Without it, every decision of the mobile facade is refused. |
| `--require-device RISKS` | `LOCKHTTP_REQUIRE_DEVICE` | none | Risk classes, comma-separated (`write`, `prod-write`), whose approvals must be signed by a pinned device, from any facade: an approval without one is a denial. The gate's asks are `write`, or `prod-write` under a production policy. Needs `--devices-file`. |
| `--seal-clear` | `LOCKHTTP_SEAL_CLEAR=1` | off | Send each ticket's clear screen (the console's, personal data unmasked) sealed to every pinned device; the hub relays ciphertext. Off, the clear screen never leaves the gate. Needs `--devices-file`. |
| `--hub-net CIDR` | | none | A network of the hub. The gate refuses as a target the hub's host name, its addresses (resolved at start) and any name resolving into these networks, even when `internal_hosts` allows private addresses; a name that does not resolve is refused too. Repeatable. Without it, the hub host must resolve at start, or the gate does not start. |
| `--check` | | off | Exit 0 if something answers on `--listen` (3 s), else 1. Starts nothing. |

**Asking the hub.** An ask becomes a plan in the gate's volume and a ticket signed
with the instance key, pushed to the hub with the screen masked (personal
data and credentials). The request answers `E_PENDING` after `hold`. A decision that verifies under the pinned hub key, for this
instance and this request's fingerprint, under the policy in force, grants
the single-use authorisation (10 minutes) or, for a `CONNECT`, the connect
grant; its nonce is consumed once. A denial answers `E_DENIED` to a waiting
request. The risk class is `write` (any part of a held request can carry data
the agent chose), `prod-write` under a production policy. The console serves
the policy; it is never asked about a request. Hub decisions are audited once (`approved`/`denied`,
`approval` `hub`, `ticket`, approver, facade, `hub_sig`); the request run
after an approval within the hold is audited `approved` with `approval`
`hub-run`, not as a second decision. An unreachable hub leaves the ask pending:
nothing falls back to another approver.

The `E_PENDING` answer names the ticket (`X-LockHTTP-Ticket`
and a `hub ticket:` line in the body); a retry of the same request waits on
the same ticket (when the hub is slow to take the ticket, past `hold`
plus one second, the `E_PENDING` may come without one). A ticket that expires undecided (24 h for `write`, 4 h for
`prod-write`) is asked again rather than refused: while the agent keeps
sending the request, the gate renews it at once; otherwise the ask ends
(`E_TIMEOUT`, audited `timeout`, naming the ticket; its hint says to send
the same request again) and the same request sent later (within 24 h, same
gate process) renews it. A renewal the human made on the hub is picked up
by the request sent again; once it ran, was denied or expired too, the
request sent again is a new ticket. A renewal is a new ticket that names
the expired one (`renews`), re-checked against the policy in force (a
changed policy is a new ticket instead); the agent's retries get
`E_PENDING` with the new ticket, and an approval lets the request through
once. A plan of the gate is the request itself, so a renewal never shows a
moved input. A human can also ask again from the hub. The plan hash inputs
the gate binds are `request` (the request fingerprint) and `policy`.

The gate keeps each ticket's clear screen (the console's screen, the body
preview masked as there) in its volume; it leaves only sealed: to a
pinned facade key (`--facade-keys-file`) on a reveal, and with
`--seal-clear` to each pinned device. Reveals and renewals asked
by the hub are audited (`reveal`/`renew`, `approval` `hub-claimed`).

**Supported lockhub versions.** Which [lockhub](https://github.com/DavidGodefroid/lockhub)
releases each lockhttp release works with. Under `lox run`, lea runs the gate in hub mode
(lockhub's `docs/lox-run.md`), and only from an `up.json` that says what the gate pins
(`"lockhttp_gate": 1`): that needs lockhub v0.2.2 or later and lea v0.3.0 or later, for every
lockhttp release below. A gate run by hand works with the hub image of the last column.
From v0.6.0 the gate is hub-attached only (there is no standalone gate): run it under `lox run`,
with a trusted `up.json` naming one lockhttp lock. lea after v0.3.5 (lea#232) then refuses to
start a gate without one and says to run `lox run`; lea v0.3.0 to v0.3.5 instead falls back to a
standalone gate, which v0.6.0 and later refuse: that gate container exits and restarts (nothing gets out).

| lockhttp | lockkit | Under `lox run` (lea's gate) | Hub image, gate run by hand |
|---|---|---|---|
| v0.8.1 | v0.14.1 | as v0.6.0 | v0.2.0 or later |
| v0.8.0 | v0.13.0 | as v0.6.0 | v0.2.0 or later |
| v0.7.1 | v0.10.0 | as v0.6.0 | v0.2.0 or later |
| v0.7.0 | v0.10.0 | as v0.6.0 | v0.2.0 or later |
| v0.6.0 | v0.9.1 | lockhub v0.2.2 + lea v0.3.0 or later, with a trusted `up.json` only: hub mode only (no standalone gate), reveals (`reveal: true`), renewals, `devices: true` | v0.2.0 or later |
| v0.5.1 | v0.8.1 | lockhub v0.2.2 + lea v0.3.0 or later: hub mode, reveals (`reveal: true`), renewals, `devices: true` | v0.2.0 or later |
| v0.5.0 | v0.6.0 | lockhub v0.2.2 + lea v0.3.0 or later: hub mode, reveals (`reveal: true`), renewals, `devices: true` | v0.2.0 or later |
| v0.4.0 | v0.4.0 | lockhub v0.2.2 + lea v0.3.0 or later: hub mode, `devices: true`; no reveals, no renewals | v0.1.1 or later; device-signed decisions from v0.2.0 (its mobile facade) |
| v0.3.0 | v0.3.1 | lockhub v0.2.2 + lea v0.3.0 or later: hub mode only | v0.1.1 or later |
| v0.2.1 and older | older than v0.3.1 | none (no hub mode) | none |

lea checks the pinned lockhttp release and never passes the gate a flag it does not know: with
`reveal: true` on a gate older than v0.5.0 it warns and pins no facade key (no reveal); with
`devices: true` on one older than v0.4.0 it warns and pins no device, or refuses to start the
gate when `require_device` or `seal_clear` is set. A gate on lockkit older than v0.5.0 ignores
the hub's reveal and renewal requests, which then time out. lockhub's
[CHANGELOG](https://github.com/DavidGodefroid/lockhub/blob/main/CHANGELOG.md) ("Supported locks")
and lea's `internal/launcher/lockhubgate.go` are the references.

The gate finds the console's socket as a lockkit client, in the socket
directory of the image's `/etc/lockhttp/system.toml`: `/run/lockhttp`, the
console's socket volume (`lox run`'s `<project>_<instance>-run`) it shares
with the console.
It polls the policy every 2 s and reloads `--sources`, `--credentials` and `--secrets`
when they change.

Clients reach the gate as an HTTP proxy: `CONNECT host:port` for HTTPS,
absolute `http://` URLs for plain HTTP. `Proxy-Authorization: Basic`
carries the agent name and token (the token is matched in `sources.json`;
without one the name is recorded as given).

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
`lox run` to pin at the hub. The first call makes the key in
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
| `lockhttp` in brew's `bin` or `~/.local/bin` | host | you | the launcher |
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
