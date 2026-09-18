# CLAUDE.md

Guidance for working in this repository. Keep it accurate to the code that exists, not
only to the design docs.

## What revika is

revika is an agnostic, modular, end-to-end-encrypted storage fabric. The Client owns names,
metadata, keys, capabilities, and consistency; untrusted Nodes/providers store only opaque
encrypted objects. See `README.md` and `docs/` for the full vision.

This repository is the **generic pure-Go core**. Native OS bindings, FUSE, the daemon's network
wiring, and most provider adapters are intentionally *not* here yet — the docs specify them as a
target contract. The exceptions are a reference **out-of-process storage adapter** for IPFS
(`internal/netframe`, `internal/ipfsstore`, `cmd/revika-ipfs-adapter`, `cmd/revika-smoke`,
`deploy/ipfs`), the first concrete instance of the §4.5.1 adapter contract, and `cmd/revika-client`,
a single-identity CLI (`cp`/`ls`/`pwd`/`rm`, `rvk:`-prefixed paths). Do not assume any other package exists just because a doc
references it (e.g. `cmd/revika-daemon`, `internal/mount`, `internal/net`, `internal/fsmeta`,
`internal/cap/pow.go` are described in docs but are **not implemented**).

## Hard constraints (do not violate)

- **cgo-free.** Everything must build and test with `CGO_ENABLED=0`. Do not `import "C"`, add
  cgo-only dependencies, or require native OS bindings. `internal/cgo_enabled_test.go` fails the
  build under `//go:build cgo` on purpose. CI sets `CGO_ENABLED=0` (`.github/workflows/go.yml`).
  Note `modernc.org/sqlite` is used precisely because it is pure Go.
- **Post-quantum crypto is mandatory.** Encryption and key establishment must be PQC-compatible
  behind versioned interfaces. **Ed25519 is permitted for signatures only** — never for key
  exchange, encryption, or capability confidentiality. AES-256-GCM (in `internal/pipeline`) is
  prototype code, not an approved waiver (see `docs/Architecture.md` §Constraints). No PQC key
  establishment exists yet: `internal/cap` capabilities carry their encryption key in cleartext
  inside the signed blob — a known capability-confidentiality gap awaiting ML-KEM wrapping. Version
  every persisted crypto format so migrations don't silently invalidate stored data.
- **Least knowledge.** Cleartext, file names, and keys live only on the Client. Never let plaintext
  or decryption keys cross into a provider/adapter/store boundary — stores hold opaque ciphertext.

## Build, test, lint

```sh
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test -race ./...
go vet ./...
gofmt -l .                # must print nothing; CI fails on any unformatted file
```

CI runs exactly: `gofmt -l` check, `go vet ./...`, `go test ./...`, all under `CGO_ENABLED=0`.
Match that before considering work done.

## Layout

Most code is under `internal/` (single Go module `github.com/revika/revika`, Go 1.25). The core is
libraries; the executables are the reference IPFS adapter binaries and the `revika-client` CLI
under `cmd/` (see below). Each package has a `_test.go` sibling; add tests with any new behaviour
and prefer table-driven tests.

| Package | Role |
| --- | --- |
| `internal/store` | Opaque content-addressed object store (`Store` interface; memory + disk impls). |
| `internal/crypto` | Versioned Ed25519 signing boundary (signatures only). |
| `internal/cap` | Signed, scoped Read/Write/Delete capabilities. |
| `internal/pipeline` | Chunking, authenticated chunk encryption, erasure (Reed-Solomon), protection, `Metadata`. |
| `internal/manifest` | Immutable content-addressed Merkle-DAG nodes; signed `RootPointer`; deterministic encoding + SHA-256 addressing. |
| `internal/rootstore` | Mutable signed root pointers with monotonic anti-rollback (memory, atomic file-backed, and sqlite-backed impls). |
| `internal/provider` | The core `Provider` contract + `Manifest` impl (COW DAG mutations, sync anchors, change diff). The stable boundary all surfaces build on. |
| `internal/placement` | Failure-domain-aware shard target selection. |
| `internal/repair` | Ciphertext-only shard repair (never decrypts). |
| `internal/crdt` | Vector clocks + deterministic text CRDT. |
| `internal/sync` | Injectable anchor-driven sync engine (conflict-copy fallback, never silently loses data). |
| `internal/db` | Pure-Go SQLite schema + numbered migrations (`modernc.org/sqlite`). |
| `internal/daemon` | Cancellable pure-Go lifecycle coordinator (no network wiring). |
| `internal/netframe` | `rvk-plugin-v1` frame codec + shared-secret handshake; `Serve` (adapter server) and `Client` (a `store.Store` over TCP). The out-of-process adapter wire protocol (§4.5.1). |
| `internal/ipfsstore` | `store.Store` backed by a Kubo node over its MFS HTTP RPC (cgo-free, `net/http` only). |
| `cmd/revika-ipfs-adapter` | Adapter binary: `netframe.Serve` in front of `ipfsstore`. First `package main` in the repo. |
| `cmd/revika-smoke` | Demo client: full store round-trip against an adapter; exits 0 on success. |
| `cmd/revika-client` | Single-identity CLI (`cp`/`ls`/`pwd`/`rm`) over `rvk:`-prefixed namespace paths; sqlite-backed identity/root pointer, per-file AES-256-GCM content encryption keyed locally. |
| `cmd/revika-client-smoke` | E2E smoke test that drives the real `revika-client` binary through a namespace round trip (cp/ls/rm); exits 0 on success. Backs the `client-ns` service of `deploy/ipfs`. |
| `cmd/revika-kubo-stub` | Pure-Go, in-memory stand-in for Kubo's MFS RPC surface. CI/test fixture only (no real storage); lets the E2E drive the real binaries without a Kubo node or the public IPFS network. |
| `deploy/ipfs` | Docker Compose stack (client, client-ns → adapter → kubo) + Dockerfile. `docker-compose.ci.yml` overlays an offline-Kubo config for the `e2e-docker` CI job. |
| `scripts/e2e.sh` | Hermetic multi-process E2E: builds the real binaries and runs client → adapter → `revika-kubo-stub` over loopback. Backs the `e2e-stub` CI job. |

The `provider.Provider` interface (`internal/provider`, mirrored in `docs/CloudStorage.md` §2) is
the central seam. `RootStore` is the one deliberately un-networked seam — keep it behind its
interface so a DHT-backed impl can drop in without touching `Provider`.

## Conventions

- Idiomatic Go: `context.Context` first arg on any operation that does I/O or can block; honour
  cancellation. Package-level sentinel errors (`ErrNotFound`, `ErrConflict`, `ErrInvalidSignature`,
  `ErrInsufficientTargets`, …) — reuse and wrap them, don't invent parallel strings.
- Determinism matters: manifest encoding, chunking, CRDT merge, and version derivation must be
  reproducible and content-addressed. Don't introduce map-iteration-order or wall-clock nondeterminism
  into serialized/hashed output; clocks are injected (`WithClock`) so tests stay deterministic.
- Every mutation publishes a **new signed root** with a strictly increasing sequence; treat a
  `RootStore.Save` rejection as a lost race (reload, re-apply, retry), not a fatal error.
- Keep the Control Plane / Storage Fabric split: naming, encryption, sharing, and conflict logic
  never leak into a store/adapter, and provider-specific details never leak up into the core.

## Docs (source of intent)

- `docs/Specifications.md` — normative requirements (PLK / ITM / SHR / DCV). The "why".
- `docs/Architecture.md` — target architecture, component contracts, SQLite schema, status table,
  PQC constraints, and the waiver process.
- `docs/CloudStorage.md` — the daemon / OS cloud-integration contract (mostly future work).

When you change a contract or land a feature the docs call "planned", update the relevant status
table so the docs don't drift from the code.
