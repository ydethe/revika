# Multi-stage, cgo-free build of the revika IPFS adapter and its E2E smoke clients. All
# binaries ship in one minimal image; the compose file selects which one each service runs.
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads separately from the source tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO must stay disabled (repo hard constraint) so the binaries are static and run on scratch.
ENV CGO_ENABLED=0
RUN go build -o /out/revika-ipfs-adapter ./cmd/revika-ipfs-adapter && \
    go build -o /out/revika-smoke ./cmd/revika-smoke && \
    go build -o /out/revika-client ./cmd/revika-client && \
    go build -o /out/revika-client-smoke ./cmd/revika-client-smoke

# Static binaries + CA certs on scratch. No shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/revika-ipfs-adapter /usr/local/bin/revika-ipfs-adapter
COPY --from=build /out/revika-smoke /usr/local/bin/revika-smoke
COPY --from=build /out/revika-client /usr/local/bin/revika-client
COPY --from=build /out/revika-client-smoke /usr/local/bin/revika-client-smoke
# Default command; overridden per-service in docker-compose.yml. Must be CMD (not ENTRYPOINT):
# Compose's `command:` overrides CMD, but is only *appended* to an ENTRYPOINT. With ENTRYPOINT,
# the client service's `command: [revika-smoke]` became an ignored argument to the adapter, so
# the client silently ran a second adapter and never exited — hanging `--exit-code-from client`.
CMD ["/usr/local/bin/revika-ipfs-adapter"]
