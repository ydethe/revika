# CLAUDE.md

Guidance for working in this repository. Keep it accurate to the code that exists, not
only to the design docs.

## What revika is

revika is an agnostic, modular, end-to-end-encrypted storage fabric. The Client owns names,
metadata, keys, capabilities, and consistency; untrusted Nodes/providers store only opaque
encrypted objects. See `README.md` and `docs/` for the full vision.

This repository is the **generic pure-Go core**. Networking, native OS bindings, FUSE, the
daemon, and provider adapters are intentionally *not* here yet — the docs specify them as a
target contract. Do not assume a package exists just because a doc references it (e.g.
`cmd/revika-daemon`, `internal/mount`, `internal/net`, `internal/fsmeta`, `internal/cap/pow.go`,
and a `revika-ctl` CLI are described in docs but are **not implemented**).

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

All code is under `internal/` (single Go module `github.com/revika/revika`, Go 1.25). There is no
`cmd/` yet — the module is libraries only. Each package has a `_test.go` sibling; add tests with
any new behaviour and prefer table-driven tests.

| Package | Role |
| --- | --- |
| `internal/store` | Opaque content-addressed object store (`Store` interface; memory + disk impls). |
| `internal/crypto` | Versioned Ed25519 signing boundary (signatures only). |
| `internal/cap` | Signed, scoped Read/Write/Delete capabilities. |
| `internal/pipeline` | Chunking, authenticated chunk encryption, erasure (Reed-Solomon), protection, `Metadata`. |
| `internal/manifest` | Immutable content-addressed Merkle-DAG nodes; signed `RootPointer`; deterministic encoding + SHA-256 addressing. |
| `internal/rootstore` | Mutable signed root pointers with monotonic anti-rollback (memory + atomic file-backed). |
| `internal/provider` | The core `Provider` contract + `Manifest` impl (COW DAG mutations, sync anchors, change diff). The stable boundary all surfaces build on. |
| `internal/placement` | Failure-domain-aware shard target selection. |
| `internal/repair` | Ciphertext-only shard repair (never decrypts). |
| `internal/crdt` | Vector clocks + deterministic text CRDT. |
| `internal/sync` | Injectable anchor-driven sync engine (conflict-copy fallback, never silently loses data). |
| `internal/db` | Pure-Go SQLite schema + numbered migrations (`modernc.org/sqlite`). |
| `internal/daemon` | Cancellable pure-Go lifecycle coordinator (no network wiring). |

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
