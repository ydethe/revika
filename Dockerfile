# syntax=docker/dockerfile:1
#
# Container image for the revika Node (cmd/revika-node) — a headless, untrusted
# blob store that serves encrypted, erasure-coded shards over libp2p and takes
# part in the Kademlia DHT. Build from the repository root:
#
#   docker build -t revika-node .
#
# Run a single node with persistent state on a named volume:
#
#   docker run --rm -p 4001:4001 -p 4001:4001/udp \
#     -v revika-data:/data revika-node
#
# The node prints its Peer ID and dialable multiaddrs on startup; use that
# /p2p/<id> address as the -bootstrap peer for other nodes and clients.

# ---- build stage -----------------------------------------------------------
# Pinned to the module's Go version; GOTOOLCHAIN=auto still fetches an exact
# match if this base ever drifts. CGO is off so the binary is fully static and
# runs on the distroless "static" runtime below.
# Pinned to the BUILD platform so cross-compilation for other target arches
# (linux/arm64 etc.) runs natively via Go's own GOOS/GOARCH rather than under
# slow QEMU emulation. buildx populates TARGETOS/TARGETARCH per requested
# platform; for a plain `docker build` they default to the host's, so behaviour
# is unchanged for single-arch local builds.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH
# Build metadata stamped into the revika-node binary via -ldflags and reported
# on startup (and on /status, /metrics). Passed by CI (see publish.yml); they
# default here so a plain local `docker build` still produces a working image.
ARG VERSION=dev
ARG BUILD_DATE=unknown
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto GOFLAGS=-mod=mod
WORKDIR /src

# Download modules first, in their own cached layer, so source-only edits don't
# re-fetch the (large) libp2p dependency tree.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Build both binaries. -trimpath drops local paths; -s -w strips debug info.
# revika-ctl is the User client, used by the `client` stage below to exercise a
# running network (put/get) from inside compose.
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}" \
      -o /out/revika-node ./cmd/revika-node && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/revika-ctl  ./cmd/revika-ctl

# A pre-owned data dir so the named/anonymous volume inherits nonroot ownership
# (distroless has no shell to chown at runtime).
RUN mkdir -p /data

# ---- runtime stage ---------------------------------------------------------
# debian-slim (not distroless) so the image ships curl, which the docker-compose
# healthcheck uses to probe the node's HTTP /healthz endpoint. We recreate the
# unprivileged "nonroot" user (uid/gid 65532, matching distroless' convention)
# so the node still runs unprivileged and owns its /data volume.
FROM debian:bookworm-slim AS node
LABEL org.opencontainers.image.title="revika-node" \
      org.opencontainers.image.description="revika headless storage Node (libp2p + Kademlia DHT)"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --home-dir /home/nonroot --create-home nonroot

COPY --from=build /out/revika-node /usr/local/bin/revika-node
COPY --from=build --chown=nonroot:nonroot /data /data

# Persistent node state: on-disk shard store + libp2p identity key. Keeping this
# on a volume gives the node a stable Peer ID across restarts.
VOLUME ["/data"]

# libp2p transports: TCP and QUIC (UDP) on the same port number.
EXPOSE 4001/tcp
EXPOSE 4001/udp
# HTTP metrics/status server (plain HTTP; front with a TLS-terminating proxy).
EXPOSE 9096/tcp

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/revika-node"]
# Default flags: fixed ports for predictable port-mapping, state under /data,
# mDNS off (it does not cross container network boundaries — use -bootstrap).
# Append -bootstrap <multiaddr> (and any overrides) after the image name.
CMD ["-data", "/data", \
     "-listen", "/ip4/0.0.0.0/tcp/4001", \
     "-listen", "/ip4/0.0.0.0/udp/4001/quic-v1", \
     "-mdns=false"]

# ---- client stage ----------------------------------------------------------
# A shell-capable image bundling the User client (revika-ctl) plus the harness
# scripts. Unlike the distroless node it needs a shell and coreutils (cmp, find,
# grep) to drive put/get and assert results, so it is based on debian-slim. Used
# by the `client` service (authorized round-trip, verify.sh — the default
# entrypoint), the `tree` service (directory round-trip, tree.sh), the
# `attacker` service (unauthorized-access checks, attack.sh), and the `deleter`
# service (delete-protection checks, delete-protection.sh), each selecting its
# script via an entrypoint override in docker-compose.yml.
FROM debian:bookworm-slim AS client
LABEL org.opencontainers.image.title="revika-ctl-testharness" \
      org.opencontainers.image.description="revika multi-node verify/attack harness (test-only, not published)"

COPY --from=build /out/revika-ctl /usr/local/bin/revika-ctl
COPY deploy/verify.sh /usr/local/bin/verify.sh
COPY deploy/tree.sh /usr/local/bin/tree.sh
COPY deploy/attack.sh /usr/local/bin/attack.sh
COPY deploy/delete-protection.sh /usr/local/bin/delete-protection.sh
COPY deploy/resilience-client.sh /usr/local/bin/resilience-client.sh
COPY deploy/repair-client.sh /usr/local/bin/repair-client.sh
RUN chmod +x /usr/local/bin/verify.sh /usr/local/bin/tree.sh /usr/local/bin/attack.sh \
      /usr/local/bin/delete-protection.sh /usr/local/bin/resilience-client.sh \
      /usr/local/bin/repair-client.sh

ENTRYPOINT ["/usr/local/bin/verify.sh"]

# ---- ctl stage (published client image) ------------------------------------
# The plain User client: just the revika-ctl binary on the same minimal
# distroless static runtime as the node (the binary is a static, CGO-free
# executable, so it needs no shell). This is the image published as revika-ctl;
# the `client` stage above is the test harness and is not published. Run e.g.:
#
#   docker run --rm -v "$PWD:/work" -w /work ghcr.io/ydethe/revika-ctl \
#     cp -bootstrap <multiaddr> -root root.json file.bin rvk:file.bin
FROM gcr.io/distroless/static-debian12:nonroot AS ctl
LABEL org.opencontainers.image.title="revika-ctl" \
      org.opencontainers.image.description="revika User client (keygen/cp/ls/rm/share/node)"

COPY --from=build /out/revika-ctl /usr/local/bin/revika-ctl
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/revika-ctl"]
