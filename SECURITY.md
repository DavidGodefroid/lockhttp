# Security policy

LockHTTP is the proxy every outbound HTTP(S) request of an AI agent goes
through. Its approval console runs on the host, in a separate account the
agent cannot reach. A flaw in either is a security issue.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories:
open <https://github.com/DavidGodefroid/lockhttp/security/advisories/new>
(the "Report a vulnerability" button on the repository's Security tab).

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Please include:

- the lockhttp version (`lockhttp version`) and your OS;
- how the agent reaches the gate (container, HTTP client), if relevant;
- the steps or input needed to reproduce the issue, and its impact.

Never include real credentials, tokens, cookies or real personal data in a
report.

You will get an acknowledgement within a week. Fixes are released as soon as
possible, and the advisory is published with credit to the reporter unless
you ask otherwise.

## Scope

Issues of interest include, among others:

- a way for an agent to send a request out without going through the gate,
  or past the gate without the human's approval where the policy requires
  it;
- a request that sends data or triggers an action but is classified as a
  read, or a host that is treated as trusted when it is not;
- a way for an agent to loosen the policy without the human's confirmation,
  or to reach the console or its socket;
- a secret reaching argv, the environment, a file, a log, the socket or an
  error message;
- agent- or server-controlled text that can spoof the console's approval
  screen;
- a decision that is not traced, or traced to the wrong container, agent or
  session.

Attacks that require running code as the console's OS account are out of
scope.

## External review

No external review of lockhttp has been done yet. Reports of a review (scope,
version or commit reviewed, method, findings, and what was not covered) are
welcome in a public issue or a pull request, once any vulnerability found has
been reported privately as above.

## Verifying a release

Each release's `checksums.txt` covers its archives and Linux packages, and is
signed keylessly by `.github/workflows/release.yml` run for the release's tag.
Check the signature against that workflow and a version tag, not any
workflow of the repository, then the file you downloaded against
`checksums.txt`:

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/DavidGodefroid/lockhttp/\.github/workflows/release\.yml@refs/tags/v[0-9]' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum -c --ignore-missing checksums.txt
```

`scripts/install.sh` runs the same check and refuses to install without
cosign (`LOCKHTTP_SKIP_COSIGN=1` is its explicit way past it).

The actions the workflows run are pinned to full commit SHAs, and the
release job pins the versions of GoReleaser, cosign and syft.

Release tags are signed with a key published on the maintainer's GitHub
profile (<https://github.com/DavidGodefroid.gpg>, or the SSH signing keys),
and a tag can be checked before you build from it:

```sh
git verify-tag vX.Y.Z
```

## Supported versions

Releases before v1.0.0 are pre-releases. Only the latest release receives
security fixes.
