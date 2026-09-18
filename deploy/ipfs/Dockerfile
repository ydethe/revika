# Multi-stage, cgo-free build of the revika IPFS adapter and smoke client. Both binaries
# ship in one minimal image; the compose file selects which one each service runs.
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads separately from the source tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO must stay disabled (repo hard constraint) so the binaries are static and run on scratch.
ENV CGO_ENABLED=0
RUN go build -o /out/revika-ipfs-adapter ./cmd/revika-ipfs-adapter && \
    go build -o /out/revika-smoke ./cmd/revika-smoke

# Static binaries + CA certs on scratch. No shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/revika-ipfs-adapter /usr/local/bin/revika-ipfs-adapter
COPY --from=build /out/revika-smoke /usr/local/bin/revika-smoke
# Default command; overridden per-service in docker-compose.yml.
ENTRYPOINT ["/usr/local/bin/revika-ipfs-adapter"]
