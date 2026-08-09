# CLAUDE.md

Guidance for Claude Code working in this repo. These instructions override default behavior.

## What revika is

A decentralized, distributed, end-to-end encrypted storage system — a self-hosted
Dropbox/Drive over a peer-to-peer network. Files are split, encrypted, and spread across
independent nodes so no single node holds a whole file and the system tolerates node loss.
See [Architecture.md](Architecture.md) for full detail; keep it and this file updated as the
code changes.

**Roles:** *User* holds the keys and stores/retrieves/shares data; *Node* is a dumb server
that stores ciphertext shards. One machine can be both. A User is a *principal* realized by one
or more *devices* under an offline *master credential* that can enroll/revoke them (planned —
Architecture §3.7.2); a device is not a third role but a member of the User principal (always
trusted with plaintext/keys). Today all a User's devices share one owner key.

## Guiding principle

**Nodes are dumb, untrusted blob stores.** They only ever see encrypted, erasure-coded shards
addressed by content hash. All intelligence (chunking, encryption, keys, sharing) lives on the
User side — a node is trusted for *availability*, never *confidentiality*.

## Design constraints (settled — treat as fixed unless the maintainer changes them)

- **Always test** All functions shall be unit-tested, and end-to-end test via docker-compose shall always be up to date. Developers shal have a way to easily generate a test coverage report
- **Never mention Tahoe-LAFS nor make design choices inspired by it** Always use Specifications and Architecture documents, and state-of-the-art concepts for cryptography and P2P sharing
- **Keep all READMEs in subpackages up to date**
- **All crypto must be PQC-class.** Cap wrapping = ML-KEM-768 (FIPS 203) via stdlib
  `crypto/mlkem` as a KEM-DEM with AES-256-GCM. AEAD = AES-256-GCM (stdlib; AES-256 is
  PQC-safe). Signatures stay Ed25519 (FIPS 204 ML-DSA not yet in stdlib).
- **Redundancy = erasure coding**, not replication: `k` data + `m` parity shards, any `k`
  reconstruct. Use `klauspost/reedsolomon`, don't hand-roll. Default `k=4`, `m=2`.
- **Networking = go-libp2p** (+ `go-libp2p-kad-dht`). Use it for discovery (Kademlia DHT on a
  private `/revika` prefix; no LAN/mDNS path — discovery is DHT-only), NAT traversal, and
  transport. Build revika protocols as versioned libp2p stream protocols; don't roll a bespoke
  wire protocol.
- **One wire version per protocol — no retro-compatibility (dev).** While revika is a
  development version, keep exactly one version of each stream protocol (`ShardProtocol`,
  `ProbeProtocol`, and the rest) in the implementation. Bump the version ID when the frame
  changes, but do *not* keep the predecessor around or serve/dial multiple versions for
  back-compat: only the current version is registered and offered, and libp2p's muxer fails
  negotiation against a mismatched peer rather than mis-framing. Peers must run matching
  builds. Node startup logs and `/status` + `/metrics` advertise the served versions.
- **Everything is encrypted client-side** before shards leave the machine.
- **Sharing = wrapping/sharing keys**, never copying plaintext. A read-capability = manifest
  location + decryption key, wrapped with the recipient's public key.
- **Repair is mandatory** — erasure coding without repair only delays data loss. Repair operates
  on ciphertext only (no decryption key), relying on `erasure.Encode` being deterministic so
  regenerated shards reproduce their content addresses.
- **Nodes may defend their own availability.** "Dumb" means dumb about *content*, not defenceless:
  an operator-run node is allowed local, operator-controlled anti-DoS/anti-DDoS defences that never
  decrypt or interpret a shard — they act only on connection/identity/volume metadata. Sanctioned
  levers: libp2p `ResourceManager` + `ConnManager` limits, a `ConnectionGater` with a
  peer/subnet blocklist (and optional allowlist), and per-peer / per-owner rate limiting keyed on
  the Ed25519 owner pubkey. Existing per-owner quota + leases stay the *storage* cap; these add a
  *flow/connection* cap. The rcmgr/connmgr/gater live in `internal/net/defense.go` (wired via
  `HostConfig.Defense`). The gater's peer set is now *runtime-mutable and persistent*
  (`net.Blocklister`): it unions the operator's static `-blocklist` with an on-disk
  `blocklist.auto` (path `-blocklist-auto`, default `<data>/blocklist.auto`) that a node's
  **maintenance-abuse detector** (`internal/net/abuse.go`, `net.AbuseMonitor`) appends bans to
  and reloads on restart. That detector locally blacklists a peer that abuses the two
  grant-authorized maintenance flows — a *too-fast* rebalancer (`ReasonRebalance` PUTs arriving
  faster than `interval − tolerance`; one violation bans) or one that racks up possession-lie
  strikes (fresh-nonce probe failures; default 3 within a decay window). Rebalance moves carry a
  trailing `MoveReason` byte on `/revika/shard/1.2.0` so the receiver distinguishes a policed
  rebalance move from schedule-exempt repair regeneration. Abuse-detector tuning
  (`-rebalance-abuse-tolerance/-coalesce/-strikes/-decay`) is a **local** defence — never
  inherited from bootstrap and never ignored on a joining node, unlike admission/maintenance
  policy. Two more *local* (never-inherited) defences are now wired the same way: an optional
  per-owner write-verb *rate* cap (`net.OwnerRateLimiter`, `internal/net/ratelimit.go`; a token
  bucket keyed on the Ed25519 owner refusing over-rate PUT/DELETE with `statusRateLimited`,
  grant-authorized repair/rebalance writes exempt; `-write-rate/-write-burst`, off by default),
  and an optional repair possession-verify (`net.RepairStore.SetVerifyPossession`,
  `-repair-verify`) that upgrades `repair.Check`'s per-shard survival test from a trusted
  `Store.Has` presence byte to a proof-of-retrieval fetch + content-address self-verify, catching
  a node that lies about holding a shard. Read-verb (`GET`/`HAS`/`PROBE`) rate limiting is still
  TODO. Note ban-by-identity is weak while identities
  are free to mint — proof-of-work identities raise the re-mint cost, but global anti-Sybil,
  reputation, and economic layers remain deferred (see Architecture.md §5).

## Toolchain & conventions

- **English only.** Every artifact in this repo is written in English — code, comments, commit
  messages, and all documentation (`*.md`, READMEs, the `security/` threat model, design docs).
  No exceptions; translate any non-English contribution before committing.
- **Formatting** prefer spaces over tabulation
- **Module path is `revika`** (bare).
- **Go 1.26** (`go 1.26` in `go.mod`). System `go` is older; leave `GOTOOLCHAIN` at its default
  (`auto`) so 1.26 auto-downloads on first build.
- **Stay cgo-free / pure Go** — e.g. SQLite via `modernc.org/sqlite`, crypto from stdlib. Prefer
  stdlib over external crypto deps; isolate swappable choices behind small interfaces.
- Match surrounding code style, naming, and comment density.
- **Structured logging only (revika-node).** Every event `revika-node` emits — startup banner,
  status, shutdown, everything — goes through the `*slog.Logger` built in
  `cmd/revika-node/logging.go` (`log.Info`/`Warn`/`Error`/`Debug` with an `event` key). Never
  `fmt.Printf`/`fmt.Println`/`fmt.Fprint*` to stdout for operational output: those bypass the
  encoder and level, so they escape the JSON path (Grafana Alloy/Loki) and can't be filtered. The
  one allowed exception is the pre-logger fatal fallback in `main()` (`run()` returned an error
  before the logger existed), which writes to `os.Stderr`.
- **Sudo commands:** don't run them — ask the maintainer to run in a separate terminal and paste
  the output.

## Commands

```bash
go build ./...            # build everything
go test ./...             # run all tests (use -race)
go test ./path/to/pkg     # test a single package
go test -run TestName ./path/to/pkg
go vet ./...
go run ./cmd/revika-node  # Node daemon (-data -listen -public-ip -dht -bootstrap
                          #   -advertise -quota -lease-ttl -gc-interval -gc-expired-leases
                          #   -repair -repair-interval -rebalance -rebalance-interval
                          #   -rebalance-threshold -capacity -metrics -blocklist
                          #   -blocklist-auto -rebalance-abuse-tolerance
                          #   -rebalance-abuse-coalesce -rebalance-abuse-strikes
                          #   -rebalance-abuse-decay -conn-low -conn-high -conn-grace
                          #   -write-rate -write-burst -repair-verify
                          #   -pow-difficulty -geoip -log-format -log-level -v)
go run ./cmd/revika-ctl   # User client: connect | keygen | cp | mv | ls | rm | share | revoke | node
                          #   | device (see -h). `ls -owner <pubkey-file>` resolves a namespace's
                          #   DHT-published root (verify-only); `revoke rvk:PATH` re-keys a shared
                          #   subtree; `device init|enroll|revoke|list|id` manages the offline
                          #   master credential's authorized read-devices (§3.7.2).
```

The client is **workspace-centric** on top of a namespace. `connect` creates a
*workspace* folder (default `.revika`, `cmd/revika-ctl/config.go`) holding a
`config.json` — the bootstrap peer(s), erasure `k`/`m` (default 4/2), and the
node's proof-of-work admission policy — alongside where `root.json` and the
User's keys (`keys/user.*`) live. `connect` takes no PoW flags: it dials the
bootstrap node(s) over libp2p (`/revika/params`, `net.QueryParams`) to read the
policy they enforce (strictest wins — max difficulty, consistent puzzle), saves
it, and mints the identity in place, grinding the signing key to that difficulty
— so the operator never re-types the policy and the workspace is write-ready. It
fails if no bootstrap node answers (a guessed policy would only surface as a late
write rejection). Every namespace command selects a workspace with `-root
<folder>`; the saved config supplies the bootstrap peers, erasure `k`/`m`, and PoW
policy so they need not be repeated. Bootstrap peers come *only* from the
workspace config (set by `connect`) — namespace commands no longer take a
`-bootstrap` flag; an explicit `-node` still overrides the backend. (If the keys
are ever absent at write time — e.g. a pre-existing workspace — the identity is
still minted lazily on the first write after a confirmation prompt.) `-root` is
overloaded: a directory is a workspace; a regular file is a bare root pointer (own
root, or a sealed shared root opened with `-key`) with no config — the historical
behaviour.

A User's files live under one mutable root directory addressed by `rvk:` paths
(e.g. `rvk:docs/report.pdf`), anchored by a signed `manifest.RootPointer`
persisted via `provider.FileRootStore` (`<workspace>/root.json`, overridable with
`-root`/`$REVIKA_ROOT`). `cp` writes/reads
scp-style (`cp file rvk:docs/` stores, `cp rvk:docs/file .` retrieves, and
`cp rvk:a rvk:b` copies within the namespace — a pure copy-on-write graft of the
source cap, no re-encryption, so both paths share shards by content address);
`mv rvk:a rvk:b` renames/moves within the namespace — the same COW graft of the
source cap at the destination plus a graft-out of the source, in one advanced
root (atomic, no re-encryption or shard movement); `ls` browses (dir blobs only,
`-l`/`-R`); `rm` grafts-out a subtree and releases
only the shards nothing under the new root still references (a keep-set diff, so a
copy's shared shards survive removing its sibling); `share rvk:PATH -to <key-file>` seals a `RootPointer` anchored at that subtree
to the recipient's ML-KEM key (a *sealed shared root* file the recipient uses as
`-root … -key <priv>` — never a bearer token); `revoke rvk:PATH` re-keys that
subtree down to its data chunks (`manifest.Rekey`), advances + republishes the
root, and reclaims the orphaned shards, so a previously-shared cap can no longer
read the current bytes (future reads only — already-downloaded copies can't be
clawed back); `node` lists DHT-discovered nodes. Own root = mutable; a shared root
= read-only. Every `cp`/`rm`/`revoke` commit also **publishes** the signed root to
the DHT (best-effort mirror behind the durable local `root.json`); `ls -owner
<pubkey-file>` resolves someone's published root, but only to its verify-cap form
(shard locations + integrity, no decryption) — a liveness/revocation inspector, not
a browse path. Commit is now a **multi-device read-merge-publish loop**
(`commitRoot`, Architecture §3.7.1): several devices sharing one owner signing key
reconcile without lost updates. Each commit reads the current DHT root; if it
diverged from this device's merge base — which **is** the durable local `root.json`
(the last root this device committed; `commitRoot` loads it as `prev` and uses
`prev.Root` as the common ancestor, so no separate base sidecar is kept) — it
three-way-merges via `manifest.Merge3` — conflicting
leaves become device-tagged conflict copies (`Config.DeviceTag`, a random 4-byte
hex minted per-workspace, never signed), never silent losses — signs at
`max(local,remote).Seq+1`, and re-reads to catch a racing writer. The decryptable
remote root reaches the other device via the **sealed self-root companion**: each
commit also publishes `manifest.FullRootRecord` (full root cap sealed to the
owner's own ML-KEM key) under DHT namespace `/revika-fullcap/<owner>`
(`net.PutFullRoot`/`GetFullRoot`), so the public verify-root stays key-stripped
while a User's own devices can still open it. `rootValidator.Select` breaks an
equal-`Seq` fork by total byte-order (not first-seen) so replicas converge. Merge
runs only with a DHT backend + owner ML-KEM keys present; otherwise commit degrades
to the prior local sign+save (+best-effort DHT mirror). A background daemon that
would reconcile an equal-`Seq` `Select`-loser that never writes again is still out
of scope. Public keys are always passed as *files*, never as literals on the
command line: `share -to <recipient-pubkey-file>` and `ls -owner <signing-pubkey-file>`
read the base64 key from the named file (no `@file` prefix, no inline key).

`device` manages the **read-revocable device model** (Architecture §3.7.2): the User
is a principal whose *master credential* is the offline owner Ed25519 signing key, and
whose *devices* are individually-keyed ML-KEM members. A signed **device-authorization
record** (`device.Auth`, `internal/device`) at `<workspace>/devices.json` (mirrored to
DHT `/revika-devices/<owner>`, `net.DeviceAuthNamespace`) lists the authorized device
pubkeys. `device init` bootstraps the record with this device; `enroll <pubkey-file>` /
`revoke <device-id>` advance it (signed by the master key) and **reseal the self-root
companion to exactly the surviving devices** by re-committing the current root — so the
companion carries one seal per device (`manifest.SealFullRootFor` → `FullRootRecord.Seals`,
coexisting with the legacy single-owner `Sealed`), and a revoked device's key opens no
current companion (`manifest.ErrNoSealForKey`). `device list`/`id` inspect the set. Absent
a `devices.json` the workspace runs the legacy single-owner-key path unchanged. Read
revocation is forward-only (already-downloaded plaintext can't be clawed back); node-enforced
*write* revocation is still deferred.

`keygen` writes two keypairs: `<prefix>.key/.pub` (ML-KEM-768, receiving shares) and
`<prefix>.sign.key/.sign.pub` (Ed25519, the storage owner identity). The signing key is
*self-certifying*: it is ground via proof-of-work (`-pow-difficulty`, default 12) until its
pubkey hashes under the target, so re-minting a banned identity costs CPU, not milliseconds
(`internal/cap/pow.go`). The puzzle is always Argon2id (`cap.Argon2idPuzzle`/`DefaultArgon2id`),
so there is nothing to negotiate — client and node agree on it implicitly. Nodes admit writes
only from owners meeting their own `-pow-difficulty` (default 0 = off), so the client's
difficulty must be ≥ the node's.

A node's role is decided purely by whether `-bootstrap` is given. Only the network's **seed**
node (no `-bootstrap`) states the cluster policy — admission (`-pow-difficulty`)
*and* maintenance (`-repair`/`-repair-interval`, `-rebalance`/`-rebalance-interval`/
`-rebalance-threshold`) — from its own flags. A **joining** node (`-bootstrap` given) inherits
that whole policy from its bootstrap peers over `/revika/params` (`net.FetchNodePolicy`, which
replaced the PoW-only `FetchPoWPolicy`: PoW strictest-wins, repair/rebalance any-enabled +
shortest interval — the same handshake `revika-ctl connect` uses for the PoW field) and runs
it, so admission *and* the maintenance cadence propagate without the operator re-typing them;
any policy flags a joining node also passes are ignored with a warning. (The one exception:
the *local* abuse-detector tuning flags are always honored — see the self-defence constraint
above.) A seed's admission opt-out is explicit: passing `-pow-difficulty` (even `0`) pins the
local policy. `cp` (store)/`rm`/`share` sign with `-signkey` (default
`.revika/keys/user.sign.key`).

Runtime state lives under `.revika/` (git-ignored): node shares, SQLite ledger, keys, mock store.

## Repo layout

```
cmd/revika-node/   headless Node daemon        cmd/revika-daemon/  (planned)
cmd/revika-ctl/    User client CLI
internal/
  store/     content-addressed blob store (Mem + Disk)
  crypto/    AES-256-GCM AEAD
  erasure/   Reed–Solomon encode/decode
  compress/  optional pre-encryption DEFLATE stage (per-chunk, skipped when it doesn't help)
  chunk/     fixed-size chunking (CDC planned)
  stripe/    non-confidential erasure metadata (Descriptor) + signed repair grant
  pipeline/  StoreFile/LoadFile + FileManifest (in-memory; serialized to local JSON by revika-ctl)
  repair/    availability probes + shard regeneration
  net/       libp2p host, shard/probe protocols, NetStore, ledger-gated Server, DHT
             (Discovery), DHTStore + PlacementStore + RepairStore, signed auth tokens
  cap/       ML-KEM-768 cap wrapping (Wrap/Unwrap) + Ed25519 signing identity
  device/    signed device-authorization record (Auth = owner-signed set of ML-KEM device
             pubkeys); read-revocable device model under the offline master credential (§3.7.2)
  ledger/    per-node SQLite ownership/lease/quota + stripe index
  manifest/  cap-addressed encrypted file/dir blobs = Merkle DAG (ReadCap, DirManifest,
             COW Graft, signed RootPointer); reuses pipeline blobs + cap wrapping
  fsmeta/    capture/restore live-file attributes ⇄ pipeline.Metadata (Linux + portable split);
             shared by revika-ctl and provider
  geoip/     coarse IP→position estimation behind a pluggable Locator (IPAPILocator now,
             opt-in; offline MaxMind .mmdb planned) for the node's /nodes dashboard map
  provider/  framework-neutral OS filesystem-integration API (Provider iface) mapping macOS File
             Provider / Windows Cloud Filter / Linux GVfs; Manifest impl over the manifest DAG with
             stable ItemIDs, DAG-diff change enumeration, and a RootStore seam for the (planned) DHT
             root publish
  placement/ node selection policy — pluggable Selector (round-robin, smooth weighted
             round-robin) + failure-domain Spread; wired into net.PlacementStore.
             OffloadBytes = the pure pairwise-diffusion rebalancing decision (§3.4)
  sync/      poll-based folder-watch daemon + three-way reconcile engine over a
             provider.Provider (bidirectional, conflict policies)
```

Terms: **shard/share** = an erasure-coded encrypted piece of a file; **ledger** = node-side
SQLite ownership/lease/quota index (`.revika/ledger/ledger.db`), *not* a blockchain; **keys** =
User ML-KEM + User Ed25519 signing + node libp2p identity; **mock store** = in-memory backend
for testing before the network layer; **device** = one enrolled, individually-keyed member of a
User principal (planned as revocable — Architecture §3.7.2); **master credential** = the offline
root of trust (owner Ed25519 key + authority to sign the device-authorization set) that enrolls
and revokes devices.

## Build order (PoC — walk before run)

Prove the core loop first (chunk → encrypt → erasure-code → distribute → retrieve → repair)
against the mock store, then swap the mock for real libp2p nodes. Sharing and the sync daemon
come after. Defer payment/incentive layers, global consensus, and Byzantine reputation.
