# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/DavidGodefroid/lockhttp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DavidGodefroid/lockhttp/releases/tag/v0.1.0
