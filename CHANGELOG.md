# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The company's managed configuration (lockkit `managed`, lockfamily
  `docs/managed.md`): lockhttp applies the `[lockhttp]` section of
  `/etc/lockfamily/managed.toml`. `[lockhttp.profiles.<name>]` are served
  as written and cannot be redefined in the policy file;
  `[lockhttp.defaults]` fill the keys a profile leaves unset;
  `[lockhttp.bounds]` (`production`, `mode`, `heuristics`, `buffer_limit`,
  `connect_grant`, `idle_timeout`, `max_session`, allowed `trusted`,
  `splice`, `redirect_cdn` and `internal_hosts`, required `deny`) is a
  ceiling the console checks at start and at every poll: a policy beyond it
  is refused (`blocked by company policy: …`, exit 3, audited
  `refused-managed`), never asked about. `[[lockhttp.bounds.rules]]` are
  deny or ask rules no user rule, grant or shadow mode lifts; they are part
  of the policy's fingerprint (`managed_rules`). Without a managed file
  nothing changes (#49).
- `lockhttp managed show` and `lockhttp managed check [--profile P]`
  (exit 3 and one line per violation; `lox` runs it before it starts the
  lock); `doctor` gains a `managed` check and checks the project's profiles
  against the bounds; `policy show` lists the managed profiles. The
  launcher mounts the host's `/etc/lockfamily` read-only for `console`,
  `policy`, `managed` and the launcher verbs (#49).

### Security

- Configuration and usage errors no longer repeat the value given, which
  may be a pasted secret or a URL with userinfo: policy errors name the key
  and, for a list, the entry's place in the file (`trusted entry 2`,
  `internal_hosts entry 1 host`, `rules entry 3`, `inject entry 1`; a rule
  or an injection by its place, not its `id` or host) with the allowed
  values; the sources file names a bad `networks` entry by its place;
  `--hub`, `--instance` (`gate` and `hub-key`), `--hub-net`,
  `--require-device`, `--allow-uid`, `--listen` (gate, `--check`, signer)
  and `doctor --gate` errors, flag parse errors, unknown commands,
  subcommands and flags (an unknown flag is named only when it looks like a
  flag name), stray arguments and "no profile of that name" omit the value.
  Profile names are keys and file paths are still named. The `mcp_servers`
  warning (shown and audited) names the server URL without its userinfo,
  query or fragment.
- The gate reloads its secrets file when its content changes even if the
  rewrite keeps the size and the mtime (a rotation within one mtime tick):
  it compares the sha256 of the content too (#44).

### Changed

- Releases are no longer GitHub pre-releases: a plain `vX.Y.Z` tag is
  published as a full release marked Latest, and only a tag with a
  pre-release suffix (`vX.Y.Z-rc.N`) stays a pre-release, as for the other
  Locks. CONTRIBUTING.md lists what v1.0.0 waits for (#44).
- `--hub` refuses a URL with a user, password, query or fragment before
  lockkit (the hub authenticates the instance key), and the gate's start
  line names the hub host only.
- The `mcp_servers` warning keeps the URL's host and path: a secret in the
  path still shows.
- lockkit v0.18.0 (#49).
- The gate checks the deny list (and the managed deny rules) on a CONNECT
  before a connect grant too, not only before decryption (#49).

### Removed

- **Breaking:** `lockhttp install` and `lockhttp setup`, which only refused
  (exit 3, "runs in Docker"): they are now unknown commands (still exit 3).
  `lox` installs and updates lockhttp (#40).

## [0.8.1] - 2026-11-07

Built on lockkit v0.14.1.

### Changed

- Docs, the agent's hints and the launcher's messages name `lox run`, which
  replaces lockhub's deprecated `lox up` (#46): `E_NO_CONSOLE` says to start
  the console with `lox run`, and so do the gate's usage error, `profile add`
  and the console's policy errors. No behavior changes: container labels,
  `up.json`, `.lockfamily/` and the flags stay the same.
- lockkit v0.14.1, whose shared texts also name `lox run`.

## [0.8.0] - 2026-11-06

Built on lockkit v0.13.0.

### Added

- Proxy-side credential injection (#38, #41). A policy `inject` entry has the
  gate add a header (e.g. `Authorization: Bearer …`) for one exact host and
  port, using a secret from its own `--secrets` file, so the agent never holds
  the credential. A request carrying such a secret is refused with
  `E_SECRET_EGRESS`, and a missing secret with the new code `E_INJECT`.

### Changed

- CI runs the macOS job on `main` and nightly, not on pull requests (#39).

## [0.7.1] - 2026-11-01

### Changed

- Docs and the default policy's comments follow the first run: `lox add lockhttp`
  sets a lock up; no auto mode (an `auto` rule asks like `ask`, every hub ticket
  is NeverAuto); the commented sample rule asks.

### Added

- Each release tag bumps the `lockhttp` formula of the
  [Homebrew tap](https://github.com/DavidGodefroid/homebrew-tap)
  (`brew install davidgodefroid/tap/lockhttp`): the release workflow's last job
  dispatches the bump once the release is signed
  (DavidGodefroid/lockfamily#8). It is skipped while the
  `TAP_DISPATCH_TOKEN` secret is not set.

## [0.7.0] - 2026-11-01

Built on lockkit v0.10.0; supported lockhub as v0.6.0. The launcher verbs
of lockkit v0.10.0 (lockkit#111, GUIDE.md §14), which `lox init` runs on
every lock (#31, #32). Breaking: `lockhttp init --trusted` is removed (now
`profile add --trusted`).

### Added

- `lockhttp profile add [--non-interactive] [--json] [--project DIR]
  [--profile NAME] [--production] [--trusted "a.com .corp.example"]`:
  adds a profile with the default policy to the project's
  `.lockhttp/config.toml`, which `lox up` reviews and copies into the
  console. A profile already there is never rewritten (code `exists`,
  nothing written); other profiles are kept byte for byte. Parsed with
  lockkit's `verbs.Parse`: a flag named like a secret, a value that embeds
  a password or a positional argument is refused, and no error quotes a
  value. lockhttp's target needs no secret: no `--credentials`, no
  `credentials` in the JSON. Without `--non-interactive` it asks on the
  terminal for the name, production and trusted hosts, and refuses
  without one. `--json` prints one `verbs.Profile` or `verbs.Error` line.
- `lockhttp init <agent>` (`claude`, `codex`, `cursor`, `gemini`): writes
  nothing (lockhttp has no agent files: lea routes the agent's HTTP
  through the gate), says so and exits 0.
- `lockhttp doctor --fix [--yes]` repairs the write permission others have
  on the project's policy or its directory, asking before each repair
  unless `--yes` (required without a terminal; `--yes` alone is a usage
  error). `--json` prints one `verbs.Doctor` (or `verbs.Error`) line.

### Changed

- `lockhttp doctor` checks the project of the current directory (its
  `.lockhttp/config.toml`, every profile unless `--profile`) instead of the
  console account's policy, and `--config` is gone.
- The launcher runs `profile`, `init` and `doctor` as you, with the
  project mounted at its own path and the current directory as the
  working directory (`profile add --project` mounted and made absolute),
  without the volume `lockhttp-home`; `policy` and `console` keep the
  console account.
- lockkit v0.10.0.

### Removed

- `lockhttp init [--profile] [--config] [--trusted] [--force]`, which
  wrote the console account's policy (pre-release, no alias). Its
  `--trusted` is now `profile add --trusted`, named after the config key
  it fills; `--profile` is `profile add --profile`.

## [0.6.0] - 2026-11-01

Hub-only release, built on lockkit v0.9.1. The gate runs hub-attached
only (lockkit#110): one mode, `lox up`'s.

### Removed

- The standalone gate. `lockhttp gate` without `--hub`, `--hub-key-file`
  and `--instance` exits with a usage error ("launched by `lox up` only");
  lea passes them from `lox up`'s `up.json`. The gate never asks a console
  about a held request any more: every ask is a hub ticket.
- The rollback of hub mode (a gate started without its hub flags
  withdrawing its pending hub tickets) and its refusal code `E_WITHDRAWN`
  (#26).
- `lockhttp console --auto`, auto mode, and the console's `http.approve`
  method: the console serves the approved policy (`policy.get`) and asks
  its human about loosenings only. A `verdict = "auto"` rule asks like
  `ask` (hub tickets are `NeverAuto`).

### Changed

- `lockhttp console` is lockkit's policy-only console
  (`console.Options.PolicyOnly`, lockkit v0.9.1): it takes no hub flags,
  as `lox up` starts it, opens no hub client and approves no request.
  Only the gate is hub-attached.
- The hub's decision on a held request is audited once, by the gate,
  with `"approval": "hub"`, the ticket, the approver and the hub's
  signature. The record of a request run after the hub approved it within
  the hold says `"approval": "hub-run"` (was `"console"`), so that
  lockhub's `lox audit verify --lock` does not read it as a second,
  unsigned hub decision.
- The agent's hints name `lox up` for `E_NO_CONSOLE` and lockhub for an
  approval.
- Docs: the quick start goes through `lox add` and `lox up`; the
  standalone quick start is gone. The launcher's docker e2e checks that
  the gate refuses to start without the hub; requests through a
  hub-attached gate are covered by the integration tests (lockkit's test
  hub) and lockhub's e2e.
- Flag help (`--devices-file`, `--facade-keys-file`), comments and docs
  name `lox`, the host CLI's name since lockhub v0.3.0 (#29).

## [0.5.1] - 2026-10-31

lockkit v0.8.1: a hub URL is `http(s)://host[:port]` only, lockkit's errors
no longer repeat the value given, and previews mask after JSON escapes.

### Security

- lockkit v0.8.1: lockkit's errors no longer repeat the value given (the
  hub URL, transport errors, instance names, `--require-device` risk
  classes, `hub-key`), and `--hub` takes `http(s)://host[:port]` only: a
  user, password, path, query, fragment, IPv6 zone, non-DNS host or bad
  port is refused (lockkit's hub client). lockhttp's own messages that
  still quote a value are addressed separately.

### Changed

- Builds on lockkit v0.8.1. The body preview and the personal-data
  heuristic read a `\n`, `\r`, `\t` or `\u0026`-style escape as the
  blank or delimiter it stands for (lockkit v0.8.0), so a phone number,
  IBAN or card number right after one in a JSON body is masked too.
- `lockhttp console` (lockkit v0.7.0, v0.7.1): a policy tightening that
  cannot be saved is applied anyway (audited, told on the console) instead
  of leaving the looser policy in force, and a change that ends the
  session no longer prints a "policy tightened" or "policy change not
  applied" line after it.

## [0.5.0] - 2026-10-30

Hub mode on lockkit v0.6.0: expired tickets are approved again, reveal from a local
facade, and a gate started without the hub withdraws its hub tickets.

Builds on lockkit v0.6.0 (reveal and re-approval; a renewal that ran or
was denied is not renewable, an expired renewal is renewed in turn).

### Added

- Hub mode: an `E_PENDING` names the hub ticket the request waits on
  (`X-LockHTTP-Ticket`).
- Re-approval of expired tickets (lockkit H1): a ticket that expires
  undecided is renewed, as a new ticket naming the expired one, while the
  agent still sends the request, or when it sends it again; the agent gets
  `E_PENDING` with the new ticket, and an approval lets the request through
  once; in hub mode `E_TIMEOUT` names the expired ticket and its hint says
  to send the same request again. Renewals re-check the plan as a run
  does (`SetRecompute`; plan inputs `request` and `policy`).
- Reveal (Ctrl-O on a local facade of the hub): `--facade-keys-file`
  (`LOCKHTTP_FACADE_KEYS_FILE`) pins the facade keys; each ticket keeps the
  console's clear screen in the gate's volume, sealed to a pinned facade
  only. Reveals and renewals asked by the hub are audited (`reveal`,
  `renew`).
- Rollback of hub mode: a gate started without the hub flags withdraws the
  tickets its hub mode left pending (the next start in hub mode tells the
  hub) and answers their request once with the new code `E_WITHDRAWN`,
  without asking the console or sending it.

### Changed

- Hub mode: the `E_TIMEOUT` reason says the ticket "expired before it was
  used" (it also covers an approval that aged before use); the security
  model (T18) says a clear screen also leaves sealed to the pinned devices
  with `--seal-clear` (#19).

## [0.4.0] - 2026-10-30

Hub mode: decisions taken on lockhub's mobile facade, signed by a pinned phone.

### Added

- Hub mode: the gate pins approval devices, with the same flags as lockkit's
  console: `--devices-file` (`LOCKHTTP_DEVICES_FILE`), `--require-device`
  (`LOCKHTTP_REQUIRE_DEVICE`) and `--seal-clear` (`LOCKHTTP_SEAL_CLEAR=1`). A
  decision of the hub's mobile facade runs only when signed by a pinned device;
  without one it is refused, as it always was before. With `--seal-clear` the
  clear screen goes to the devices sealed, the hub relaying ciphertext. Uses
  lockkit's device decisions (`hubclient.Config.Devices`).

## [0.3.0] - 2026-10-30

Hub mode: the gate can hand its asks to lockhub instead of its own console.

### Changed

- Hub mode: an `http://` `--hub` URL is refused unless the host is a loopback address, or
  `--hub-plain-http` (`LOCKHTTP_HUB_PLAIN_HTTP=1`) is given for a hub on a network of its
  own (a service name without a dot or a private address); redirects from the hub are
  refused and the hub state file must be private (lockkit#57).

### Added

- Hub mode for the gate (`--hub`, `--hub-key-file`, `--instance`, `--home`,
  `--hub-net`): asks become signed tickets on lockhub, and a verified
  decision grants the existing single-use authorisation or connect grant.
  The gate refuses the hub's addresses as targets, even with
  `internal_hosts`. `lockhttp hub-key` prints the instance key to pin.
  Builds on lockkit v0.3.1 (hub support).

## [0.2.1] - 2026-10-28

### Fixed

- `lockhttp ca init` under rootless Podman: the launcher adds
  `--userns keep-id`, so the CA files are written as the invoking user
  (they failed with "permission denied" on a subuid).
- The image's `lockhttp version` prints `0.2.1`, not `v0.2.1`, like the
  release archives and the launcher.

## [0.2.0] - 2026-10-28

### Changed (breaking)

- LockHTTP runs in Docker only. On the host, `lockhttp` is now a launcher,
  a POSIX shell script (`scripts/lockhttp`) that runs every command in the
  release image, each as the account it needs: `console` as `lockhttp`
  (uid 10021) in the container `lockhttp-console`, with no log driver and the
  volumes `lockhttp-run` and `lockhttp-home`; `init`, `policy` and `doctor`
  as `lockhttp`; `gate` as `gate` (uid 10003, in `lockhttp-clients`) with
  `lockhttp-run`, published on `127.0.0.1:3130`; `signer` as `signer`
  (uid 10004); `ca` as the invoking user. See `docs/docker.md`.
- `scripts/install.sh` installs the launcher, not a binary: it verifies the
  cosign signature of `checksums.txt` and of the image, and writes the
  image's verified digest into the launcher, which runs it by digest
  (`LOCKHTTP_SKIP_COSIGN=1`: by tag, unverified). It warns when a former
  host install (`/etc/lockhttp/system.toml`) remains.
- lea integration (`docs/lea.md`): the gate and the signer run as sidecar
  containers from the image (`--network container:<prefix>-proxy`,
  `--user gate`, volume `lockhttp-run`). No `allowed_uids`, subuid mapping,
  `--group-add`, host `/run/lockhttp` or `LOCKHTTP_RUNTIME_DIR`. The file
  formats are unchanged (contract version 1).
- `lockhttp doctor` no longer checks that the binary is root-owned, and
  reports `allowed_uids` only when set.

### Added

- The image `ghcr.io/davidgodefroid/lockhttp:X.Y.Z` (amd64, arm64), built
  by the release workflow and signed with cosign; a `Dockerfile` with the
  accounts `lockhttp`, `gate` and `signer` and the build argument
  `ALLOWED_UIDS`.
- `lockhttp policy show|edit|path [--config FILE]`: print, edit (with a parse
  check) or locate the console account's policy.
- `lockhttp update [vX.Y.Z]` and `lockhttp version` in the launcher: a
  release's launcher, checked as `install.sh` does, then `docker pull`; the
  launcher's and the image's versions.
- `LOCKHTTP_IMAGE`, `LOCKHTTP_DOCKER_ARGS` and `LOCKHTTP_PUBLISH` for the
  launcher.
- CI: the image built and driven through the launcher end to end
  (`test/docker/e2e.py`).

### Removed

- `lockhttp install` (and `setup`): the image refuses them. The host account
  `lockhttp`, the group `lockhttp-clients`, `/etc/lockhttp/system.toml`,
  `/run/lockhttp` and the host binary are no longer created; see "Migrating
  from a host install" in `docs/docker.md`.
- The `.deb`, `.rpm` and `.apk` packages. Release archives now carry the
  launcher.

## [0.1.0] - 2026-10-28

First pre-release. Phase 0 and 1 of the design (CONNECT + SNI gate in front
of squid, interactive traced allowlist), with phase 2 decryption (local CA,
separate signer, Claude API allowlist) available behind `--ca-cert` and
`--signer`. Built on lockkit v0.2.1.

### Added

- `lockhttp gate`: the HTTP(S) proxy. CONNECTs are decided at the domain
  (an approval opens reads AND writes, and the screen says so), or decrypted
  per request when a CA and a signer are given. Plain HTTP is decided per
  request. Verdicts FREE, ASK, DENY; refusals answer `403` with
  `X-LockHTTP-Code` and `X-LockHTTP-Request`.
- Hard floor no policy loosens: IP literals, DoH, cloud metadata names,
  ports other than 80/443 (except an internal host's declared ports),
  single-label hosts, SNI different from the CONNECT host, an incomplete or
  missing ClientHello on 443, `Upgrade: h2c`, nested CONNECT, a Host header
  that differs from the target. Direct mode never dials a non-public address.
- Policy (`~/.config/lockhttp/config.toml` of the console account): trusted
  read hosts, splice and deny lists, internal hosts, redirect CDNs, rules
  (`free`, `auto`, `ask`, `deny`) scoped to a container or to all, never to
  an agent; `mode = "shadow"` and `heuristics = "shadow" | "enforce" | "off"`.
  `auto` is refused on messaging, registry publishing, `git-receive-pack`,
  spliced hosts, every-host rules and production profiles.
- Claude API allowlist (decrypted): `/v1/messages` free only without
  `mcp_servers`, `container` or a server tool other than `web_search`;
  ambiguous JSON asks; `/v1/files` asks; a credential that is not the
  container's is denied; other Anthropic hosts and paths ask (`NeverAuto`).
- Secret egress denial (GitHub, Anthropic, AWS, Slack, OpenAI, Google, npm,
  GitLab tokens and private keys outside their hosts) and an exfiltration
  score (URL size, entropy, subdomains, headers, personal data), logged in
  shadow by default.
- `lockhttp console`: lockkit's console on the host, in its own account
  (`http.approve`, `policy.get`). Every screen is `NeverAuto` unless an
  approved `auto` rule matches, re-checked by the console itself. Masked body
  preview, git push refs, pending count, "client gone" note.
- Ask queue: one approval at a time; identical fingerprints (container,
  method, URL, significant headers, normalised body) share a decision, other
  bodies are separate items; `E_PENDING` after the hold time, then a
  single-use authorisation (10 min) once approved.
- Fail-closed: no console → asks refused at once (`E_NO_CONSOLE`), trusted
  reads go on with the last approved policy; unknown source → `E_SOURCE_UNKNOWN`.
- lea integration (`docs/lea.md`, contract v1): `sources.json` (container by
  local address, agent by Proxy-Authorization, keyproxy via `X-Lea-Source`),
  `credentials.json`, status file, gate JSONL audit (daily, 30 days).
- `lockhttp signer` (holds the CA key, issues 24 h leaves to allowed uids)
  and `lockhttp ca init` (P-256, pathlen 0, 90 days).
- `lockhttp install` (console account, clients group, `allowed_uids` for the
  gate, rootless subuid mapping), `lockhttp init`, `lockhttp doctor`.
- Release pipeline: goreleaser, cosign keyless signatures, SBOMs,
  SHA-pinned actions, `scripts/install.sh` with signature verification.

[Unreleased]: https://github.com/DavidGodefroid/lockhttp/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.8.1
[0.8.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.8.0
[0.7.1]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.7.1
[0.7.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.7.0
[0.6.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.6.0
[0.5.1]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.5.1
[0.5.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.5.0
[0.4.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.4.0
[0.3.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.3.0
[0.2.1]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.2.1
[0.2.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.2.0
[0.1.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.1.0
