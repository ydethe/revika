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
FROM golang:1.26-bookworm AS build
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
    go build -trimpath -ldflags='-s -w' -o /out/revika-node ./cmd/revika-node && \
    go build -trimpath -ldflags='-s -w' -o /out/revika-ctl  ./cmd/revika-ctl

# A pre-owned data dir so the named/anonymous volume inherits nonroot ownership
# (distroless has no shell to chown at runtime).
RUN mkdir -p /data

# ---- runtime stage ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS node
LABEL org.opencontainers.image.title="revika-node" \
      org.opencontainers.image.description="revika headless storage Node (libp2p + Kademlia DHT)"

COPY --from=build /out/revika-node /usr/local/bin/revika-node
COPY --from=build --chown=nonroot:nonroot /data /data

# Persistent node state: on-disk shard store + libp2p identity key. Keeping this
# on a volume gives the node a stable Peer ID across restarts.
VOLUME ["/data"]

# libp2p transports: TCP and QUIC (UDP) on the same port number.
EXPOSE 4001/tcp
EXPOSE 4001/udp

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
# A shell-capable image bundling the User client (revika-ctl) plus the
# end-to-end verify script. Unlike the distroless node it needs a shell and
# coreutils (cmp, find) to drive put/get and assert results, so it is based on
# debian-slim. Used by the `client` service in docker-compose.yml.
FROM debian:bookworm-slim AS client
LABEL org.opencontainers.image.title="revika-ctl" \
      org.opencontainers.image.description="revika User client + multi-node verify harness"

COPY --from=build /out/revika-ctl /usr/local/bin/revika-ctl
COPY deploy/verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh

ENTRYPOINT ["/usr/local/bin/verify.sh"]
