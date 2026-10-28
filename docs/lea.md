# LockHTTP in lea: the integration contract

This is what lea (the agent launcher) must do to put LockHTTP on the egress
path of its agents, and what LockHTTP guarantees in return. The lea side
lives in the lea repository; this page is the contract both sides test
against. Contract version: **1** (the `version` field of every file below).

```
 agent container  (<prefix>-internal-<id>, --internal)
   HTTP(S)_PROXY=http://<agent>:<token>@lea-proxy:3130
   LockHTTP CA in the trust stores (when MITM is on)
          │
 <prefix>-proxy container
   lockhttp gate  :3130  (uid 10003, never 0)  ──▶ squid 127.0.0.1:3128 ──▶ Internet
   lockhttp signer (uid 10004, MITM only) ◀─ leaf certificates ─ gate
   keyproxy :4400 ──▶ gate (127.0.0.1:3130, keyproxy token + X-Lea-Source)
          │ /run/lockhttp/user-<profile>.sock (bind mount, proxy container only)
 host
   lockhttp console --profile <profile>   (account lockhttp, its own session)
```

## 1. Host setup (once, by the human)

| Step | Command | Notes |
|---|---|---|
| Install the binary | `scripts/install.sh` or a release archive | `/usr/local/bin/lockhttp`, root-owned. |
| Separate the console | `sudo lockhttp install --client <lea user> --gate-uid 10003 [--rootless]` | Creates the `lockhttp` account, the `lockhttp-clients` group (the lea user joins it), `/run/lockhttp` (`lockhttp:lockhttp-clients`, 2710) and `/etc/lockhttp/system.toml`. `allowed_uids` gets the gate's uid **as the host sees it**: `10003` under rootful Docker; under rootless Podman (`--rootless`) the subuid `subuid_base + 10003 - 1` read from `/etc/subuid` for the lea user. |
| Write the policy | as `lockhttp`: `lockhttp init [--trusted "<LEA_EGRESS_ALLOW>"]` | Writes `~lockhttp/.config/lockhttp/config.toml` (profile `default`). `--trusted` imports lea's allowlist as trusted read-only hosts (D-optin). lea never writes this file. |
| Start the console | as `lockhttp`, in its own login session: `lockhttp console --profile default` | lockkit's isolation checks refuse any other shape. |

## 2. Proxy container: the gate

lea runs the gate in `<prefix>-proxy` when `LEA_LOCKHTTP=1`.

### 2.1 Process

```
lockhttp gate \
  --listen 0.0.0.0:3130 \
  --upstream http://127.0.0.1:3128 \
  --profile default \
  --sources /etc/lockhttp-gate/sources.json \
  --credentials /etc/lockhttp-gate/credentials.json \
  --audit-dir /var/log/lockhttp \
  --status-file /run/lockhttp-gate/status.json \
  [--ca-cert /etc/lockhttp-gate/ca.pem --signer /run/lockhttp-signer/signer.sock]
```

| Item | Value | Why |
|---|---|---|
| uid | dedicated, **never 0** (10003 by default) | uid 0 in a rootless container is the lea user on the host, which `CheckIsolation` refuses as a client. |
| Environment | `LOCKHTTP_RUNTIME_DIR=/run` | The gate dials `$LOCKHTTP_RUNTIME_DIR/lockhttp/user-<profile>.sock`. |
| Mounts | host `/run/lockhttp` → `/run/lockhttp` (the socket dir, **proxy container only**, never an agent container) | The console authenticates the gate with `SO_PEERCRED` against `allowed_uids`. |
| Groups | Docker rootful: `--group-add <gid of lockhttp-clients>`; Podman rootless: `--group-add keep-groups` (crun) | The socket directory is `2710 lockhttp:lockhttp-clients`. |
| Files (read-only bind mounts, written by lea on the host) | `sources.json`, `credentials.json`, `ca.pem` | Reloaded when they change (2 s poll). An unreadable or invalid file is fail-closed (see §2.3). |
| Writable | `--audit-dir` (persist it on the host, e.g. `~/.local/state/lea/lockhttp/audit/`), `--status-file` dir | JSONL audit of FREE and DENY, daily files, 30 days kept. |
| Liveness | `lockhttp gate --check --listen 127.0.0.1:3130` exits 0 when the gate answers | For lea's doctor. |

### 2.2 Network rules lea must apply (security requirements)

1. **squid listens on `127.0.0.1:3128` only** (`render-squid-conf.sh`), so the gate is the only HTTP way out. Its floor (DoH, IP literals, private ranges, ports) stays; its hard allowlist is switched off when `LEA_LOCKHTTP=1` (the gate decides).
2. **keyproxy goes through the gate**: `-via http://keyproxy:<keyproxy token>@127.0.0.1:3130`, with `X-Lea-Source: <container>` and the same `Proxy-Authorization` set on the CONNECT (`http.Transport.ProxyConnectHeader`). keyproxy strips any `X-Lea-Source` and `Proxy-Authorization` an agent sends. The gate honours `X-Lea-Source` only from 127.0.0.1 with the keyproxy token; elsewhere it is ignored and logged.
3. **SSH git forwarders are off**: lea refuses to start the proxy with a non-empty `LEA_GIT_SSH` when `LEA_LOCKHTTP=1`.
4. **Nested Podman** (`image/containers.conf.tmpl`): `HTTPS_PROXY=http://nested:<container token>@lea-proxy:3130`.
5. Agent env: `HTTP_PROXY`/`HTTPS_PROXY=http://<agent>:<agent token>@lea-proxy:3130`. `NO_PROXY` may keep `lea-proxy` (keyproxy on 4400 is reached directly; squid is no longer reachable).
6. The gate refuses connections arriving on the interface of the default route (the egress side), fail-closed.

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
no file, the check is off and `lockhttp doctor` says so.

## 3. MITM (phase 2, optional)

| Step | Who | What |
|---|---|---|
| CA | lea, on the host | `lockhttp ca init --dir ~/.local/state/lea/lockhttp/ca` → `ca.pem` (public) and `ca-key.pem` (0600). P-256, `pathlen:0`, 90 days; `lockhttp ca init --force` rotates. |
| Signer | proxy container, its own uid (10004) | `lockhttp signer --ca-cert ca.pem --ca-key ca-key.pem --listen /run/lockhttp-signer/signer.sock --allow-uid 10003`. Only the signer can read `ca-key.pem` (bind mount read-only, owned by its uid). |
| Gate | proxy container | `--ca-cert ca.pem --signer /run/lockhttp-signer/signer.sock`. The gate never holds the CA key. |
| Trust stores | `image/entrypoint` (root phase, before `setpriv`) | `ca.pem` into `/usr/local/share/ca-certificates/lockhttp.crt` + `update-ca-certificates`; `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`; nested Podman: mount the PEM in `/etc/containers/certs.d/`. Never the key. |
| keyproxy | | trusts `ca.pem` (`RootCAs`). |

Hosts in the policy's `splice` list (and internal hosts) are not decrypted:
they are decided at the domain, as in phase 1.

## 4. What the gate tells the agent

| Case | Response |
|---|---|
| FREE | the upstream response; header `X-LockHTTP-Request: <id>` on decrypted or plain HTTP responses |
| DENY | `403`, headers `X-LockHTTP-Code: E_*`, `X-LockHTTP-Request: <id>`, a text body: why, and what to ask of the human |
| ASK pending past the hold time (60 s) | `403 E_PENDING`: the item stays on the console; once approved, the same request goes through (single-use authorisation, 10 min) |
| No console | `403 E_NO_CONSOLE`, body: "the human must run: lockhttp console --profile <p>" |

For a CONNECT, the refusal is the CONNECT's own `403` (clients show it as a
proxy error).

## 5. What lea reads back

- **Status file** (`--status-file`, JSON, rewritten on change):
  `{"version":1, "console": "up|down", "pending": 2, "pending_by_container": {"lea-ab12cd34ef": 2}, "policy_fp": "sha256:…", "updated": "…"}`.
  The deck shows the counter and plays a sound on the first ASK (D6). It is
  a notification only: approvals happen in the console, never in the deck.
- **Audit**: gate JSONL in `--audit-dir` (`gate-YYYY-MM-DD.jsonl`), console
  audit in `~lockhttp/.local/state/lockhttp/audit.log`; both carry
  `request_id`, `container`, `agent`, `attribution`, `via`.

## 6. Doctor checks for lea

- gate answers (`lockhttp gate --check`), squid listens on loopback only;
- `LEA_GIT_SSH` empty;
- from an agent: `curl --noproxy '*' https://example.com` fails;
  `curl -x http://lea-proxy:3128 https://example.com` fails;
  `curl https://example.com` without a console → `E_NO_CONSOLE` (or FREE for trusted);
- a keyproxy call appears in the gate audit with `via: "keyproxy"`;
- MITM on: `ca.pem` valid for more than 7 days, signer answers.
