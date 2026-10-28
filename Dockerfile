# lockhttp in Docker: every lockhttp command runs in this image, through
# the launcher (scripts/lockhttp). The separated setup is baked in:
#
#   lockhttp (uid 10021)  the console account: it alone shows approvals and
#                         keeps the policy (volume lockhttp-home)
#   gate     (uid 10003)  the proxy, a member of lockhttp-clients: it reaches
#                         the console's socket (volume lockhttp-run)
#   signer   (uid 10004)  holds the CA key for decryption, nothing else
#
# The kernel checks every peer on the socket as on a host. See
# docs/docker.md and docs/lea.md.
#
#   docker build -t lockhttp .
#
# The base images are pinned by digest: update the tag and the digest
# together (docker buildx imagetools inspect golang:1.26-alpine).

FROM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/lockhttp ./cmd/lockhttp

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
# ALLOWED_UIDS: comma-separated uids that may reach the console besides the
# members of lockhttp-clients (a gate run as another uid). Never root (0)
# nor the console's own uid (10021).
ARG ALLOWED_UIDS=""
# ca-certificates: the gate checks every upstream certificate against them.
RUN case "$ALLOWED_UIDS" in *[!0-9,]*|,*|*,|*,,*) echo "ALLOWED_UIDS: comma-separated uids, got '$ALLOWED_UIDS'" >&2; exit 1;; esac \
 && for u in $(echo "$ALLOWED_UIDS" | tr ',' ' '); do \
      case "$u" in 0*|10021) echo "ALLOWED_UIDS: $u is root or the console account (or has a leading zero)" >&2; exit 1;; esac; \
    done \
 && apk add --no-cache ca-certificates \
 && addgroup -S -g 10020 lockhttp-clients \
 && adduser -D -u 10021 -s /bin/sh -g "lockhttp console" lockhttp \
 && adduser -D -H -u 10003 -G lockhttp-clients -s /sbin/nologin -g "lockhttp gate" gate \
 && adduser -D -H -u 10004 -s /sbin/nologin -g "lockhttp signer" signer \
 && chmod 0700 /home/lockhttp \
 && install -d -m 0755 -o root -g root /etc/lockhttp \
 && printf '%s\n' \
      '# lockhttp: the console runs as service_user; members of client_group reach it.' \
      'service_user = "lockhttp"' \
      'client_group = "lockhttp-clients"' \
      'socket_dir   = "/run/lockhttp"' \
      'x11          = "refuse"' > /etc/lockhttp/system.toml \
 && if [ -n "$ALLOWED_UIDS" ]; then printf 'allowed_uids = [%s]\n' "$ALLOWED_UIDS" >> /etc/lockhttp/system.toml; fi \
 && chmod 0644 /etc/lockhttp/system.toml \
 && install -d -m 2710 -o lockhttp -g lockhttp-clients /run/lockhttp \
 && install -d -m 0700 -o gate -g lockhttp-clients /var/log/lockhttp
COPY --from=build --chown=root:root --chmod=0755 /out/lockhttp /usr/local/bin/lockhttp

# Named volumes take these directories' owner and mode on first use.
VOLUME ["/run/lockhttp", "/home/lockhttp"]
WORKDIR /
USER gate
ENTRYPOINT ["lockhttp"]
CMD ["help"]
