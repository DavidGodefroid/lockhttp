# LockHTTP in lea: the integration contract

This is what lea (the agent launcher) must do to put LockHTTP on the egress
path of its agents, and what LockHTTP guarantees in return. The lea side
lives in the lea repository; this page is the contract both sides test
against. Contract version: **1** (the `version` field of every file below).

> **Hub-attached only (after v0.5.1).** The gate always asks lockhub: it
> does not start without `--hub`, `--hub-key-file` and `--instance`
> ("launched by `lox up` only"), and there is no standalone gate asking a
> console of its own. lockhub's `lox up` runs the lockhttp console (it
> serves the policy) and the hub, and writes in `<workspace>/.lockfamily/up.json`
> what lea passes to the gate (lockhub's `docs/lox-up.md`). Without a
> trusted `up.json` naming one lockhttp lock, lea does not start the gate
> and says to run `lox up`. The console's socket volume is `lox up`'s
> `<project>_<instance>-run`, no longer `lockhttp-run`.

> **Changes since v0.1.0.** LockHTTP runs in Docker only
> ([docker.md](docker.md)). There is no host install any more: no
> `sudo lockhttp install`, no `lockhttp` account or `lockhttp-clients` group
> on the host, no `allowed_uids`, no subuid mapping, no `--group-add`, no
> host `/run/lockhttp` bind mount, no `LOCKHTTP_RUNTIME_DIR`. The human runs
> the console in a container through the launcher; lea runs the gate (and
> the signer) as sidecar containers from the same image, by digest. The file
> formats (`sources.json`, `credentials.json`, the status file) are
> unchanged: contract version 1.

```
 agent container  (<prefix>-internal-<id>, --internal)
   HTTP(S)_PROXY=http://<agent>:<token>@lea-proxy:3130
   LockHTTP CA in the trust stores (when MITM is on)
          │
 <prefix>-proxy container  (network namespace shared with the gate)
   squid 127.0.0.1:3128 ──▶ Internet
   keyproxy :4400 ──▶ gate (127.0.0.1:3130, keyproxy token + X-Lea-Source)
 <prefix>-lockhttp-gate container  (--network container:<prefix>-proxy)
   lockhttp gate :3130  (uid 10003 "gate", in lockhttp-clients)  ──▶ squid 127.0.0.1:3128
 <prefix>-lockhttp-signer container  (MITM only)
   lockhttp signer  (uid 10004 "signer") ◀─ leaf certificates ─ gate (socket volume)
          │ volume <project>_<instance>-run: /run/lockhttp/user-<profile>.sock
 console container  (lox up's service lock-<instance>)
   lockhttp console --profile <profile>  (uid 10021 "lockhttp")
          ·
   the gate ──▶ lockhub (lox up's network <project>_lockhub; only <prefix>-proxy joins it)
```

## 1. Setup (once, by the human)

| Step | Command | Notes |
|---|---|---|
| Install the launcher | `scripts/install.sh` ([docker.md](docker.md#install-and-update)) | `/usr/local/bin/lockhttp`, root-owned. It checks the cosign signatures and writes the verified image digest into itself (`image_digest=` line). |
| The lock and its policy | `lox add lockhttp <instance>`, the policy in `<workspace>/.lockhttp/config.toml` | lockhub's `lox`. lea never writes the policy. |
| Start the hub and the console | `lox up` | Runs the hub and the lockhttp console (uid 10021, no log driver) in compose services, makes the gate's instance key in the gate's own volume (`<project>_<instance>-gate`) and registers it with the hub, and writes `up.json`. `lox attach <instance>` attaches the console's terminal (its first policy review). |

lea never starts the console and never mounts the console's home.

## 2. The gate container

lea runs the gate as a sidecar of `<prefix>-proxy` when `LEA_LOCKHTTP=1`.

### 2.1 Process

```
docker run -d --name <prefix>-lockhttp-gate \
  --network container:<prefix>-proxy \
  --user gate \
  -v <project>_<instance>-run:/run/lockhttp \
  -v <project>_<instance>-gate:/lockhttp-home \
  -v <state>/lockhttp/gate/hub:/run/lockfamily:ro \
  -v <state>/lockhttp/gate:/etc/lockhttp-gate:ro \
  -v <state>/lockhttp/audit:/var/log/lockhttp \
  -v <state>/lockhttp/status:/run/lockhttp-gate \
  ghcr.io/davidgodefroid/lockhttp@sha256:<digest> \
  gate \
    --listen 0.0.0.0:3130 \
    --upstream http://127.0.0.1:3128 \
    --profile default \
    --sources /etc/lockhttp-gate/sources.json \
    [--credentials /etc/lockhttp-gate/credentials.json] \
    --audit-dir /var/log/lockhttp \
    --status-file /run/lockhttp-gate/status.json \
    [--ca-cert /etc/lockhttp-gate/ca.pem --signer /run/lockhttp-signer/signer.sock] \
    --hub http://lockhub:<port> --hub-plain-http --hub-key-file /run/lockfamily/hub.pub \
    --instance <instance> --home /lockhttp-home --hub-net <hub network subnet> ... \
    [--facade-keys-file /run/lockfamily/facades.json] \
    [--devices-file /run/lockfamily/devices.json [--require-device RISKS] [--seal-clear]]
```

The hub flags are required: `up.json` gives every value (lockhub's
`docs/lox-up.md`, "Why lockhttp is different"), and the gate refuses to
start without them.

| Item | Value | Why |
|---|---|---|
| Image | `ghcr.io/davidgodefroid/lockhttp@sha256:<digest>` | The digest the launcher pins (its `image_digest=` line, `grep '^image_digest=' "$(command -v lockhttp)"`), or the one `cosign verify` prints ([SECURITY.md](../SECURITY.md#verifying-the-image)). Never a tag. The gate and the console should run the same release. |
| Network | `--network container:<prefix>-proxy` | The gate shares the proxy container's network namespace: the `local_ip` mapping of `sources.json`, squid on `127.0.0.1:3128` and keyproxy's `127.0.0.1:3130` stay as they were. |
| uid | `--user gate` (10003, **never 0**) | In the image, uid 10003 is in `lockhttp-clients`, the group the console accepts. Nothing to configure on the host: no `allowed_uids`, no subuid, no `--group-add`. The gate refuses to run as root. |
| Socket | volume `<project>_<instance>-run` (`up.json`'s `socket_volume`) → `/run/lockhttp` (**the gate's container only**, never an agent container) | The console's socket. The image's `/etc/lockhttp/system.toml` names `/run/lockhttp`; the console checks the gate's uid with `SO_PEERCRED`. The volume belongs to the Docker engine `lox up` uses: lea must start the gate on that same engine. |
| Hub | volume `<project>_<instance>-gate` → `--home`; lea's copies of the hub key, facade keys and devices, read-only | The gate's instance key, plans and hub state. Only the proxy container joins the hub's network; the gate refuses its addresses as targets. |
| Files (read-only, written by lea on the host) | `<state>/lockhttp/gate/` → `/etc/lockhttp-gate`: `sources.json`, `credentials.json`, `ca.pem` | Readable by uid 10003. Reloaded when they change (2 s poll). An unreadable or invalid file is fail-closed (see §2.3). |
| Writable | `--audit-dir` (`/var/log/lockhttp`, persisted on the host), the `--status-file` directory | Writable by uid 10003. JSONL audit of every decision (FREE, DENY, ask outcomes), daily files, 30 days kept. |
| Liveness | `docker exec <prefix>-lockhttp-gate lockhttp gate --check --listen 127.0.0.1:3130` | Exits 0 when the gate answers. For lea's doctor. |

The `<state>/...` paths are lea's choice; only the in-container paths
above are the ones the flags name.

### 2.2 Network rules lea must apply (security requirements)

1. **squid listens on `127.0.0.1:3128` only** (`render-squid-conf.sh`), so the gate is the only HTTP way out. Its floor (DoH, IP literals, private ranges, ports) stays; its hard allowlist is switched off when `LEA_LOCKHTTP=1` (the gate decides).
2. **keyproxy goes through the gate**: `-via http://keyproxy:<keyproxy token>@127.0.0.1:3130`, with `X-Lea-Source: <container>` and the same `Proxy-Authorization` set on the CONNECT (`http.Transport.ProxyConnectHeader`). keyproxy strips any `X-Lea-Source` and `Proxy-Authorization` an agent sends. The gate honours `X-Lea-Source` only from 127.0.0.1 with the keyproxy token; elsewhere it is ignored and logged.
3. **SSH git forwarders are off**: lea refuses to start the proxy with a non-empty `LEA_GIT_SSH` when `LEA_LOCKHTTP=1`.
4. **Nested Podman** (`image/containers.conf.tmpl`): `HTTPS_PROXY=http://nested:<container token>@lea-proxy:3130`.
5. Agent env: `HTTP_PROXY`/`HTTPS_PROXY=http://<agent>:<agent token>@lea-proxy:3130`. `NO_PROXY` may keep `lea-proxy` (keyproxy on 4400 is reached directly; squid is no longer reachable).
6. The gate serves only the local addresses listed in `sources.json` (one per internal network) and loopback with the keyproxy token: a connection arriving on any other address, the egress side included, is refused (`E_SOURCE_UNKNOWN`), fail-closed. Bind the gate where agents can reach it, never expose it on the egress bridge.

### 2.3 `sources.json`: who is calling

The container is read from the **local address the connection arrived on**:
the proxy container has one address per internal network, so the address
names the network, and the network names the container. That is the safe
part. The agent name comes from `Proxy-Authorization` and is audit only
(agents of one container share a uid: attribution, not authentication).

```json
{
  "version": 1,
  "networks": [
    {"local_ip": "10.89.3.2", "container": "lea-ab12cd34ef", "project": "shop"}
  ],
  "keyproxy": {"token_sha256": "<hex sha256 of the keyproxy token>"},
  "agents": [
    {"token_sha256": "<hex>", "container": "lea-ab12cd34ef", "agent": "dev-5",
     "role": "dev", "parent": "claude-1", "task_id": "", "branch": "feat/x", "session_id": ""},
    {"token_sha256": "<hex>", "container": "lea-ab12cd34ef", "agent": "nested"}
  ]
}
```

- A connection whose local address is not in `networks` (and is not the
  keyproxy on 127.0.0.1) is refused: `E_SOURCE_UNKNOWN`.
- An agent token that belongs to another container than the network says is
  ignored for attribution (`attribution: "ambiguous"`) and logged.
- Agent `nested` marks nested Podman (`attribution: "nested"`).
- Tokens are compared by sha256; the file never holds a token.
- lea rewrites the file atomically (write + rename) when an agent starts,
  stops or changes task; the gate picks it up within 2 s.

### 2.4 `credentials.json`: whose keys (MITM only)

```json
{
  "version": 1,
  "containers": {"lea-ab12cd34ef": ["<hex sha256 of an OAuth access token or API key>"]},
  "keyproxy": ["<hex sha256 of each provider key keyproxy injects>"]
}
```

lea's daemon hashes each container's Claude credentials
(`state/claude/<id>/`) at start and whenever the file changes (OAuth
rotates). On the Claude API, an `Authorization: Bearer` or `x-api-key`
whose hash is not in the caller's list is denied (`E_SECRET_EGRESS`). With
no file (no `--credentials`), the check is off.

## 3. MITM (phase 2, optional)

| Step | Who | What |
|---|---|---|
| CA | lea, on the host, through the launcher | `lockhttp ca init --dir ~/.local/state/lea/lockhttp/ca --name <installation>` → `ca.pem` (public) and `ca-key.pem` (0600). The launcher runs it as the invoking user, with the directory mounted at its own path: both files belong to that user. P-256, `pathlen:0`, 90 days; `--force` rotates. Without `--name`, the launcher passes the machine's name (`uname -n`). The key stays readable by the user who ran it, so keep `--dir` out of any directory an agent container mounts (lea's state dir, not a project), and once the key is copied to the signer's volume (below), the host copy can be removed or kept 0600 for rotation. |
| CA key to the signer | lea | `ca-key.pem` must be owned by uid 10004 (`signer`), mode 0600, mounted read-only in the signer's container only. For example, copy it into a volume with a one-off root container of the same image: `docker run --rm --user 0 --entrypoint sh -v ~/.local/state/lea/lockhttp/ca:/src:ro -v <prefix>-lockhttp-ca:/ca IMAGE@sha256:<digest> -c 'install -m 0600 -o signer /src/ca-key.pem /ca/ca-key.pem && install -m 0644 /src/ca.pem /ca/ca.pem'`. |
| Signer socket directory | image | A named volume on `/run/lockhttp-signer`, shared by the signer and the gate. The image's directory is `signer:lockhttp-clients`, mode `2750`, and a new named volume takes it on first use: the socket (mode 0660) gets group `lockhttp-clients`, so the gate can connect and nothing else in the proxy namespace can. |
| Signer | its own container, uid 10004 | `docker run -d --name <prefix>-lockhttp-signer --network none --user signer -v <prefix>-lockhttp-ca:/etc/lockhttp-ca:ro -v <prefix>-lockhttp-signer:/run/lockhttp-signer IMAGE@sha256:<digest> signer --ca-cert /etc/lockhttp-ca/ca.pem --ca-key /etc/lockhttp-ca/ca-key.pem --listen /run/lockhttp-signer/signer.sock --allow-uid 10003`. The signer refuses a key readable by group or others. |
| Gate | the gate's container | Add `-v <prefix>-lockhttp-signer:/run/lockhttp-signer` and `--ca-cert /etc/lockhttp-gate/ca.pem --signer /run/lockhttp-signer/signer.sock` (lea copies `ca.pem` into `<state>/lockhttp/gate/`). The gate never holds the CA key. |
| Trust stores | `image/entrypoint` (root phase, before `setpriv`) | `ca.pem` into `/usr/local/share/ca-certificates/lockhttp.crt` + `update-ca-certificates`; `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`; nested Podman: mount the PEM in `/etc/containers/certs.d/`. Never the key. |
| keyproxy | | trusts `ca.pem` (`RootCAs`). |

Hosts in the policy's `splice` list (and internal hosts) are not decrypted:
they are decided at the domain, as in phase 1.

## 4. What the gate tells the agent

| Case | Response |
|---|---|
| FREE | the upstream response; header `X-LockHTTP-Request: <id>` on decrypted or plain HTTP responses |
| DENY | `403`, headers `X-LockHTTP-Code: E_*`, `X-LockHTTP-Request: <id>`, a text body: why, and what to ask of the human |
| ASK pending past the hold time (60 s) | `403 E_PENDING` naming the hub ticket (`X-LockHTTP-Ticket`): once approved on the hub, the same request goes through (single-use authorisation, 10 min) |
| No console | `403 E_NO_CONSOLE`, body: "No lockhttp console is running: ask the user to start it (lox up)." |

For a CONNECT, the refusal is the CONNECT's own `403` (clients show it as a
proxy error).

## 5. What lea reads back

- **Status file** (`--status-file`, JSON, rewritten on change):
  `{"version":1, "console": "up|down", "pending": 2, "pending_by_container": {"lea-ab12cd34ef": 2}, "policy_fp": "sha256:…", "updated": "…"}`.
  The deck shows the counter and plays a sound on the first ASK (D6). It is
  a notification only: approvals happen on the hub's facades.
- **Audit**: gate JSONL in `--audit-dir` (`gate-YYYY-MM-DD.jsonl`), console
  audit in the console account's `~/.local/state/lockhttp/audit.log`, in
  the console's home volume, which lea does not mount; the hub's audit; both carry
  `request_id`, `container`, `agent`, `attribution`, `via`.

## 6. Doctor checks for lea

- gate answers (`docker exec <prefix>-lockhttp-gate lockhttp gate --check --listen 127.0.0.1:3130`),
  squid listens on loopback only;
- the gate runs the pinned digest (`docker inspect`), as `gate`, with
  the console's socket volume on `/run/lockhttp` and never the console's
  home or the Docker socket;
- `LEA_GIT_SSH` empty;
- from an agent: `curl --noproxy '*' https://example.com` fails;
  `curl -x http://lea-proxy:3128 https://example.com` fails;
  `curl https://example.com` without a console → `E_NO_CONSOLE` (or FREE for trusted);
- a keyproxy call appears in the gate audit with `via: "keyproxy"`;
- MITM on: `ca.pem` valid for more than 7 days, signer answers, `ca-key.pem`
  mounted in the signer's container only.
