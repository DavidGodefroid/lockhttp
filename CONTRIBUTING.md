# Contributing to lockhttp

Thanks for your interest. Bug reports, fixes and new test cases are welcome.
For security issues, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Before you start

- For anything beyond a small fix, open an issue first to agree on the
  approach. lockhttp is a security tool: features that loosen a default, add
  a way around the gate or the console, or add a dependency need a clear
  case.
- Code, comments, docs and commit messages are in English.
- Design decisions are recorded in [docs/decisions.md](docs/decisions.md).
- By contributing you agree that your work is licensed under the Apache
  License 2.0.

## Where the code lives

The product-neutral half of lockhttp (console socket and protocol, peer
checks, approvals, terminal, isolation checks, secrets, audit log, config
lookup and the approved-policy store, personal-data detectors, output
caps, error scrubbing, signature checks, MCP plumbing, agent wiring) lives
in [lockkit](https://github.com/DavidGodefroid/lockkit), shared with the
other lock* tools; its GUIDE.md is the contract. This repository keeps what
is HTTP: the gate (the proxy), request classification, the host and method
policy, the HTTP refusal codes, lockhttp's console modes and start-up, its
MCP tools and its agent texts.

lockkit is pinned in `go.mod`. Do not copy a lockkit package here or work
around it: a change to a shared package is asked for and made in lockkit
first, as described in
[GUIDE.md §13, Asking for a lockkit change](https://github.com/DavidGodefroid/lockkit/blob/main/GUIDE.md#13-asking-for-a-lockkit-change);
lockhttp then pins the new lockkit version. To work on both at once, add an
uncommitted `go.work` (`use (. ../lockkit)`, listed in `.git/info/exclude`).

## Build

```sh
CGO_ENABLED=0 go build ./cmd/lockhttp
```

Requires Go 1.26 or later. Every target builds with `CGO_ENABLED=0`; keep
dependencies pure Go.

## Tests

lockhttp is developed test first: write the failing test, then the code
that makes it pass.

```sh
go vet ./...
go test ./...
```

The module also builds for Windows, where lockhttp refuses to run, and CI
runs the unit tests on `windows-latest`. A test file that needs Unix
accounts, file modes, sockets or terminals starts with `//go:build unix`; a
single test skips with `t.Skip` and the reason. To check that the tests
still compile for Windows:

```sh
GOOS=windows go vet ./...
GOOS=windows go test -exec /bin/true ./...
```

### Integration tests

Integration tests start the gate, the console and test upstream servers
in-process, on `127.0.0.1`; they need no Docker and no network access.

```sh
go test -tags integration ./test/integration/...
```

Never point a test at a real remote service.

### Launcher tests

`scripts/lockhttp` and `scripts/install.sh` are tested by `go test` in
`cmd/lockhttp` (Unix only): `launcher_test.go` runs the launcher with a fake
`docker` that records each call (the account, the volumes and the flags of
every subcommand, `update`); `installsh_test.go` runs `install.sh` against a
fake release and a fake `cosign`. They run with the unit tests:

```sh
go test ./cmd/lockhttp -run 'Launcher|InstallSh'
```

When you change what a subcommand runs, change the table in
[docs/docker.md](docs/docker.md#subcommand--docker-run) with it.

### Docker end-to-end test

`test/docker/e2e.py` builds nothing itself: it drives an image through the
launcher as a user would. The console runs in a pseudo-terminal the script
answers, the gate in its own container, and `curl` sends requests through
the gate's published port. It needs Docker, `curl`, Python 3 (standard
library only) and network access to `example.com`:

```sh
docker build -t lockhttp .
LOCKHTTP_IMAGE=lockhttp python3 test/docker/e2e.py
```

It uses the launcher's real names (`lockhttp-console`, `lockhttp-gate`,
volumes `lockhttp-run` and `lockhttp-home`) and removes them: do not run it
on a machine with a lockhttp setup you want to keep. CI runs it in the
`docker` job, after checking that a build with `ALLOWED_UIDS=0` fails.

## Pull requests

- Write the failing test first, then the fix.
- Keep `gofmt`, `go vet`, `staticcheck` and `govulncheck` clean, and
  `sh scripts/hygiene.sh` passing.
- Keep the security invariants: no secret in argv, environment, files, logs,
  the socket protocol or error strings; no protocol method that loosens the
  policy; fail closed on anything ambiguous.
- One logical change per pull request, with a commit message that explains
  why.

Pull requests target `main`, which is protected:

- the CI checks (`test` on Linux, macOS and Windows, `lint`, `integration`,
  `docker`)
  must pass and the branch must be up to date with `main`;
- a review from a code owner is required, and every review thread must be
  resolved;
- pull requests are squash-merged: the title becomes the commit subject and
  the description its body, so write both for the history. Use a
  [conventional commit](https://www.conventionalcommits.org/) prefix
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...).

Workflows on pull requests from forks run after a maintainer approves them.
Participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## Releases

Releases are built by GoReleaser (`.goreleaser.yaml`) when a `v*` tag is
pushed: `.github/workflows/release.yml` runs the unit tests, then builds
linux and darwin archives on amd64 and arm64 (each with the launcher),
signs `checksums.txt` with cosign (keyless) and attaches an SBOM per
archive. Its `image` jobs build the image on native amd64 and arm64
runners, push `ghcr.io/davidgodefroid/lockhttp:X.Y.Z-ARCH`, join them in
the manifest `:X.Y.Z` and sign it with cosign by digest. Until
v1.0.0, every release is published as a GitHub pre-release. To check the
configuration locally without signing or publishing (needs `goreleaser`,
and `syft` for the SBOMs):

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=sign
```

The output goes to `dist/`, which is ignored by git.

The release chain is pinned end to end:

- every `uses:` in `.github/workflows/` names a full commit SHA with its
  version as a comment (`actions/checkout@<sha> # v7.0.1`); Dependabot bumps
  both. Check a new SHA is the tag's commit (`gh api
  repos/OWNER/REPO/commits/vX.Y.Z --jq .sha`) and keep the comment exact;
- `release.yml` pins the GoReleaser, cosign and syft versions and does not
  use `check-latest`;
- the cosign identity is the release workflow run for a version tag, the
  same in `scripts/install.sh`, `scripts/lockhttp`, `SECURITY.md` and
  `.goreleaser.yaml`;
- the `Dockerfile` pins its base images by digest: update the tag and the
  digest together.

Tags are created by the maintainer only. Sign release tags:

```sh
git tag -s vX.Y.Z -m "lockhttp vX.Y.Z"   # with gpg.format=ssh for an SSH key
git verify-tag vX.Y.Z
```

with a key published on the maintainer's GitHub profile, which is where
`SECURITY.md` sends users to verify it.
