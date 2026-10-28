# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/DavidGodefroid/lockhttp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.2.0
[0.1.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.1.0
