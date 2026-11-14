# lockhttp in Docker

lockhttp runs in Docker, with nothing on your machine but Docker and the
`lockhttp` launcher. The launcher is a short POSIX shell script
([`scripts/lockhttp`](../scripts/lockhttp)): every command you type,
`lockhttp profile add`, `lockhttp console`, `lockhttp gate` and the others, runs in
the lockhttp image, each with the account and the volumes it needs. There is
no other `lockhttp` on the host.

## What is installed

| Where | What |
|---|---|
| host | the launcher `lockhttp`: brew's `bin` (`brew install davidgodefroid/tap/lockhttp`) or `~/.local/bin` ([lockfamily's install.sh](https://github.com/DavidGodefroid/lockfamily/blob/main/docs/install.md)) |
| registry | `ghcr.io/davidgodefroid/lockhttp:X.Y.Z`, amd64 and arm64, signed with cosign by the release workflow; the launcher runs it by digest |
| release archives | the launcher (`scripts/lockhttp`), the binary, `LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md`, `SECURITY.md`; brew and lockfamily's install.sh take only the launcher |

No host packages (`.deb`, `.rpm`, `.apk`), no host binary, no system
account on the host.

## The image

The image ([`Dockerfile`](../Dockerfile)) holds the separated setup that
`sudo lockhttp install` used to create on the host:

| Account | uid | Groups | Role |
|---|---|---|---|
| `lockhttp` | 10021 | its own | the console account: it alone shows approvals and keeps the policy; not a member of `lockhttp-clients` |
| `gate` | 10003 | `lockhttp-clients` (gid 10020) | the proxy; as a member of the clients group it reaches the console's socket. The image's default user. |
| `signer` | 10004 | its own | holds the CA key for decryption, nothing else |

- `/etc/lockhttp/system.toml` (root, `0644`): `service_user = "lockhttp"`,
  `client_group = "lockhttp-clients"`, `socket_dir = "/run/lockhttp"`,
  `x11 = "refuse"`, and `allowed_uids` when the image is built with
  `ALLOWED_UIDS` ([below](#build-the-image-yourself)).
- `/usr/local/bin/lockhttp` (root, `0755`): the binary, the entrypoint.
- `/run/lockhttp` (`2710 lockhttp:lockhttp-clients`): the console's socket
  directory.
- `/home/lockhttp` (`0700`): the console account's home.
- `/var/log/lockhttp` (`0700 gate:lockhttp-clients`): a directory for the
  gate's audit (`--audit-dir`).

The console checks every peer on its socket with the kernel's peer
credentials, as on a host: the gate is accepted because uid 10003 is in
`lockhttp-clients` inside the image.

### Volumes

| Volume | Mounted at | Shared by | Holds |
|---|---|---|---|
| `lockhttp-run` | `/run/lockhttp` | the console and the gate | the console's socket, `user-<profile>.sock` |
| `lockhttp-home` | `/home/lockhttp` | the console account's commands only (`console`, `policy`) | the policy `~/.config/lockhttp/config.toml`, the approved policy and the console's audit (`~/.local/state/lockhttp/`) |

A named volume takes the owner and mode of the image's directory on first
use, so `lockhttp-run` is `2710 lockhttp:lockhttp-clients` and
`lockhttp-home` is `0700 lockhttp`.

## Subcommand → `docker run`

Every run is `docker run --rm $LOCKHTTP_DOCKER_ARGS ... IMAGE ...`, with
`-it` when stdin and stdout are terminals, else `-i`.
`LOCKHTTP_DOCKER_ARGS` is split on spaces and never globbed. Every container
the launcher starts (but `version` and `help`) is confined: `--cap-drop ALL
--security-opt no-new-privileges --read-only --tmpfs
/tmp:rw,nosuid,nodev,noexec,size=64m --pids-limit 256 --memory 1g`; the
volumes stay writable. A path holding `:` (which `docker -v` cannot mount) is
refused.

| Subcommand | Account | `docker run` arguments | Why |
|---|---|---|---|
| `console` | `lockhttp` (10021) | `--name lockhttp-console --log-driver none --user lockhttp -v lockhttp-run:/run/lockhttp -v lockhttp-home:/home/lockhttp` | the only container with `lockhttp-home`; no log driver, so `docker logs` keeps no approval screen; a stopped container named `lockhttp-console` is removed first |
| `policy` | `lockhttp` | `--user lockhttp -v lockhttp-home:/home/lockhttp` | it reads or edits the policy in the console account's home |
| `profile`, `init`, `doctor` | you (`id -u`:`id -g`) | `--user UID:GID -v ROOT:ROOT -w CWD`: ROOT is the project of the current directory (the nearest directory holding `.lockhttp/config.toml`, else `.git`, else the current directory), or `profile add`'s `--project DIR`, made absolute; under rootless Podman also `--userns keep-id`; no lockhttp volume | the launcher verbs `lox add` runs: they write and check the project's `.lockhttp/config.toml`, which is yours |
| `gate` | `gate` (10003) | `--name lockhttp-gate --user gate -v lockhttp-run:/run/lockhttp -p ${LOCKHTTP_PUBLISH:-127.0.0.1:3130}:3130`, and `--listen 0.0.0.0:3130` unless you pass `--listen` | it needs the hub flags, and refuses to start without them; lea starts its own gate ([lea.md](lea.md)) |
| `signer` | `signer` (10004) | `--user signer -v lockhttp-signer:/run/lockhttp-signer` | the socket directory (`signer:lockhttp-clients`, 2750, from the image) the gate shares; lea runs its own signer ([lea.md](lea.md#3-mitm-phase-2-optional)) |
| `ca` | you (`id -u`:`id -g`) | `--user UID:GID -v DIR:DIR`, with `--dir DIR` made absolute (created 0700) and `--name $(uname -n)` unless you pass `--name`; under rootless Podman also `--userns keep-id`, so that the files are yours on the host | the CA files are yours; lea reads `ca.pem` and gives `ca-key.pem` to the signer alone |
| `version` | `gate` | | prints `lockhttp launcher X (image I)`, then runs `I version` |
| `update [vX.Y.Z]` | (host) | | [below](#install-and-update) |
| anything else (`help`, ...) | `gate` (image default) | | |

Invariants: the Docker socket is never mounted; only the console's
container gets `lockhttp-home`; the gate shares only `lockhttp-run` with
the console.

The `ca` command creates `DIR` on the host (`mkdir -p`) before it starts
the container, then mounts it at its own path.

### The company's managed configuration

When this machine has the Lock Family's managed directory
(`/etc/lockfamily` on Linux, `/Library/Application Support/lockfamily` on
macOS: [configuration.md](configuration.md)), the launcher mounts it
read-only on `/etc/lockfamily` in every container it runs (`-v
DIR:/etc/lockfamily:ro`, before `$LOCKHTTP_DOCKER_ARGS`), the path the
image reads `managed.toml` from, as `lox run` mounts it in its locks. So
`lockhttp managed show`, `managed check`, `policy`, `doctor`, `profile`,
`init`, the console and the gate see the bounds the locks enforce. The
whole directory is mounted: the signature bundle, `signer.toml` and the
`managed.toml.verified` stamp come along. Ownership is checked in the
container as on the host (a bind mount keeps owner and mode): the file and
the directory must be root's and writable by root only. No directory: no
mount, and lockhttp runs without a managed policy. A path that is not a
directory (a file, a dangling link) or holds a `:` stops the launcher
before `docker run`.

On macOS, Docker Desktop shares `/Users`, `/Volumes`, `/private`, `/tmp`
and `/var/folders` only: add `/Library/Application Support/lockfamily` in
Settings > Resources > File sharing, or the launcher's commands fail with
`mounts denied` (never without the policy).

## Version pinning

The installer (brew, lockfamily's install.sh) and `lockhttp update` write two
lines of the launcher:

```sh
launcher_version=X.Y.Z
image_digest=sha256:...   # ghcr.io/davidgodefroid/lockhttp:X.Y.Z
```

The digest comes from `cosign verify` of the image against the release
workflow run **for that very tag**
(`https://github.com/DavidGodefroid/lockhttp/.github/workflows/release.yml@refs/tags/vX.Y.Z`,
`--certificate-identity`, never a regular expression: a tag moved onto an
older release's signed files does not verify), the same check as for `checksums.txt` (
[SECURITY.md](../SECURITY.md#verifying-the-image)), so the launcher runs
`ghcr.io/davidgodefroid/lockhttp@sha256:...`, never a tag that could move.
With `LOCKHTTP_SKIP_COSIGN=1` nothing is verified: `image_digest` stays
empty and the launcher runs `ghcr.io/davidgodefroid/lockhttp:X.Y.Z`. A
launcher run from a clone (`launcher_version=dev`) runs the local image
`lockhttp`.

`lockhttp version` prints the launcher's version and the image it runs, then
the image's own version.

## Overrides

- `LOCKHTTP_IMAGE`: the image to run instead of the pinned one (your own
  build, an image built with `ALLOWED_UIDS`);
- `LOCKHTTP_DOCKER_ARGS`: extra `docker run` arguments, split on spaces,
  placed before the launcher's own (`-d`, `--network NAME`,
  `-v /path/ca.pem:/path/ca.pem:ro`);
- `LOCKHTTP_PUBLISH`: where `lockhttp gate` publishes its port (default
  `127.0.0.1:3130`).

## Install and update

Install the launcher with Homebrew or lockfamily's install.sh
([install.md](install.md#install)). `lockhttp update [vX.Y.Z]` replaces an
installed launcher with a release's:

0. check that the version is a release tag (`vX.Y.Z[-pre]`): it goes into
   URLs and into the launcher's text;
1. download the release archive for this OS and architecture,
   `checksums.txt` and its sigstore bundle;
2. `cosign verify-blob` the bundle against the release workflow identity,
   then check the archive's sha256;
3. extract `scripts/lockhttp` (a release without it predates the launcher
   and is refused);
4. `cosign verify` the image `ghcr.io/davidgodefroid/lockhttp:X.Y.Z` and take
   its digest;
5. write the version and the digest into the launcher and install it over
   itself, mode `0755`, with `sudo` when needed;
6. run `docker pull` of the pinned image.

Any failed check stops before the launcher is replaced. cosign is required;
`LOCKHTTP_SKIP_COSIGN=1` is the explicit way past it, and then neither the
signature nor the image is verified. Without a version, `update` takes the
newest entry of the releases feed. A launcher installed by brew is updated
by `brew upgrade` instead.

## Platforms

- **Linux**: Docker Engine.
- **macOS**: Docker Desktop; the same launcher.
- **Windows**: no native build. Install the launcher in WSL 2 with Docker
  Desktop's WSL integration and run it there.

amd64 and arm64 only.

## Quick start (hub-attached)

lockhttp runs hub-attached only: there is no standalone gate. lockhub's
`lox run` runs the console (in a compose service of its own, with the
policy it reviewed from `<workspace>/.lockhttp/`) and the hub, and lea runs
the gate beside its proxy with the hub flags `lox run` writes in
`.lockfamily/up.json` ([install.md](install.md#quick-start-with-lea),
[lea.md](lea.md)). `lockhttp gate` without `--hub`, `--hub-key-file` and
`--instance` exits with a usage error ("launched by `lox run` only").

`lox add lockhttp` writes the policy through the launcher verbs, from the project
root: `lockhttp profile add --non-interactive --json --profile NAME`
(`<workspace>/.lockhttp/config.toml`), `lockhttp init claude` (nothing to
write) and `lockhttp doctor --fix --yes --json`. They run as you on the
project; run them by hand the same way.

The launcher's own `console` and `policy` still run the image as the
console account with the volume `lockhttp-home`, the policy `lox run`
would copy there. To try the launcher's console by hand, copy the
project's policy into the volume first:

```sh
docker run -i --rm --user lockhttp -v lockhttp-home:/home/lockhttp --entrypoint sh lockhttp \
  -c 'umask 077 && mkdir -p ~/.config/lockhttp && cat > ~/.config/lockhttp/config.toml' < .lockhttp/config.toml
```

## Build the image yourself

From a clone:

```sh
docker build -t lockhttp .
LOCKHTTP_IMAGE=lockhttp lockhttp console
```

The launcher of a clone (`sh scripts/lockhttp ...`) runs the image tagged
`lockhttp` by default. `--build-arg VERSION=X.Y.Z` sets the version that
`lockhttp version` prints.

`ALLOWED_UIDS` is a comma-separated list of uids that may reach the console
besides the members of `lockhttp-clients`, written to `allowed_uids` in the
image's `/etc/lockhttp/system.toml`: for a gate that runs as another uid
than 10003. Root (`0`), the console's uid (`10021`) and uids with a leading
zero are refused at build time.

```sh
docker build -t lockhttp --build-arg ALLOWED_UIDS=1000 .
```

## Migrating from a host install

v0.1.0 installed a `lockhttp` binary on the host, and `sudo lockhttp
install` created there:

- the account `lockhttp` (with a home and a password if you set one) and
  the group `lockhttp-clients`, which your account joined;
- `/etc/lockhttp/system.toml`;
- `/etc/tmpfiles.d/lockhttp.conf` and the socket directory `/run/lockhttp`
  (Linux);
- `/usr/local/bin/lockhttp`, a root-owned copy of the binary.

Install the launcher ([install.md](install.md#install)), then remove the
old root-owned binary (`sudo rm /usr/local/bin/lockhttp`): lea looks in
`/usr/local/bin` first. The rest stays until you remove it. First keep the
old policy: it becomes the project's.

```sh
mkdir -p -m 0700 .lockhttp
sudo cat ~lockhttp/.config/lockhttp/config.toml > .lockhttp/config.toml   # the old policy
lockhttp doctor --fix                                                       # checks it
```

The console shows the whole policy for approval at its first start. Then
remove the host install (Linux):

```sh
sudo userdel -r lockhttp            # the account and its home: old policy, approved policy, audit
sudo groupdel lockhttp-clients
sudo rm -r /etc/lockhttp /run/lockhttp
sudo rm /etc/tmpfiles.d/lockhttp.conf
```

`userdel -r` deletes the old console's audit with its home: copy
`~lockhttp/.local/state/lockhttp/` first if you need it. On macOS the host
install used `/usr/local/var/run/lockhttp` for the sockets and no tmpfiles
entry:

```sh
sudo sysadminctl -deleteUser lockhttp
sudo dseditgroup -o delete lockhttp-clients
sudo rm -r /etc/lockhttp /usr/local/var/run/lockhttp
```

lea no longer needs `--gate-uid`, `--rootless`, the subuid mapping, a
`--group-add` or the host's `/run/lockhttp`: it runs the gate from the
image ([lea.md](lea.md)).

## What Docker does and does not separate

The gate's container reaches the console only through the socket in
`lockhttp-run`; it has no policy file and cannot approve. The agent never
gets that volume, nor the Docker socket.

Your own account is another matter. Whoever can run `docker` on the host
can `docker attach` to `lockhttp-console` and type an approval, `docker
exec` into it, or open `lockhttp-home` in another container and edit the
approved policy. An agent that runs shell commands in an account allowed to
use Docker can do the same. Keep the agent in a container without the
Docker socket, as lea does: it then reaches the network only through the
gate. More in [security-model.md](security-model.md).
