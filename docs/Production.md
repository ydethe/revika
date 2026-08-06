# Production readiness

Status snapshot: **2026-08-06.** What separates today's tree from a production
self-hosted Drive. See [Architecture.md](../Architecture.md) for the full design;
this file only tracks the gaps.

The engineering baseline is strong for the current stage: a green `go test -race`
suite, multi-node/resilience/repair end-to-end jobs in CI, multi-arch image
publishing, `/healthz` `/readyz` `/status` `/metrics` endpoints, structured `slog`
logging, up-front policy discovery (`/revika/params` → `net.FetchNodePolicy`, so
admission *and* maintenance cadence propagate to joining nodes and to
`revika-ctl connect` instead of surfacing as late failures), proof-of-work owner
identities, and a maintenance-abuse detector with a persistent `blocklist.auto`.
The gaps below are at three levels — architectural blockers first, then hardening
the design already calls for, then deferred layers and ops polish.

## 1. Architectural blockers — not a working distributed product yet

- **The mutable root pointer is now published, but has no production hardening.**
  `manifest.RootPointer` is persisted to a durable local `root.json`
  (`internal/provider/file_rootstore.go`) and published to the DHT keyed by the
  owner pubkey (`internal/net/root.go`, `provider.DHTRootStore`/`MultiRootStore`),
  with a complementary `/revika/root/1.0.0` node stream (`root_proto.go`). A 12h
  `RepublishRootLoop` refreshes it before the DHT's 48h record expiry.
  `revika-ctl` publishes on every `cp`/`rm`/`revoke` commit and resolves by
  `ls -owner <pubkey>`. What remains for production: republish scheduling for the
  *client* (today only a node with a root would run the loop; a client publishes
  synchronously on commit), and multi-device write reconciliation (§3.7 sync).
- **Manifest and directory blobs are encrypted.** `StoreFileManifest`/`StoreDir` go
  through `pipeline.StoreBlob` → AES-256-GCM, so the namespace is ciphertext at rest
  like file data (build-order step 4 done).
- **Capability chain is complete; revocation denies future reads only.** Cap
  *delivery* (ML-KEM wrap/unwrap) plus the write-cap → read-cap → verify-cap
  derivation chain (`internal/manifest`) and the Ed25519 signing identity for the
  mutable root all exist. **Revocation is implemented** by re-keying
  (`manifest.Rekey` → `revika-ctl revoke`): the shared subtree is re-encrypted down
  to data chunks, the root advances, and orphaned shards are reclaimed. Honest limit
  — it revokes *future* reads; bytes/keys a recipient already downloaded cannot be
  clawed back.
- **Sync daemon and mount are absent as products.** `internal/sync` has the
  reconcile/poll logic but there is **no `cmd/revika-daemon` binary** — it runs only
  in tests. The FUSE / OS-mount layer (§3.8) is entirely planned. The actual
  end-user surface (a folder that syncs) does not ship.

## 2. Hardening the design already calls for

- **Write-verb rate limiting on PUT/DELETE now ships (optional).** A per-owner token
  bucket (`net.OwnerRateLimiter`, `internal/net/ratelimit.go`) meters fresh
  owner-initiated writes keyed on the Ed25519 owner, refusing an over-rate write with
  the new `statusRateLimited` response; grant-authorized repair/rebalance writes are
  exempt (as with PoW admission). It is wired via `Server.SetRateLimiter` from
  `revika-node -write-rate/-write-burst`, off by default, and — like the abuse-detector
  tuning — a **local** defence, never inherited from bootstrap. This joins the
  connection/rcmgr defenses (`internal/net/defense.go`) and the maintenance-abuse
  blocklister (`internal/net/abuse.go`, `AbuseMonitor`). **Still open:** per-peer/IP
  rate limiting on the anonymous read verbs (`GET`/`HAS`/`PROBE`).
- **Repair can now verify shard possession instead of trusting `Store.Has` (optional).**
  By default `repair.Check` still reads a single presence byte
  (`internal/repair/repair.go` → `NetStore.Has`), which a lying node defeats. With
  `revika-node -repair-verify` the repairer's `net.RepairStore`
  (`SetVerifyPossession`) upgrades each remote survival check to a **proof of
  retrieval**: it fetches the shard and self-verifies its content address
  (`hash == ID`), so a node that lies "I hold it" is caught and the shard counts as
  missing (→ regenerated). It costs a shard download per remote check, so it is
  opt-in and a **local** defence (never inherited). (The fresh-nonce
  `/revika/probe/1.0.0` proof-of-possession — used by **rebalance**'s
  make-before-break release, `internal/net/rebalance.go` — needs the verifier to hold
  the shard bytes, which a repairer does not for remote positions, so repair uses the
  self-verifying fetch instead.) Repair-onto-fresh-nodes and repair cadence/threshold
  policy remain open.
- **Placement diversity only partly enforced on moves**: rebalance now caps
  per-peer stripe concentration (never let one peer hold more than `m` shards of a
  stripe, `rebalance.go` `peerStripeLoad`) with a proof-gated release, but the
  failure-domain `Spread` invariant (`internal/placement/spread.go`) is still not
  applied on moves, capacity (`LoadReport`/`QueryLoad`) is self-declared and
  untrusted, and the per-shard cooldown is in-memory (lost on restart).
- **Fixed-size chunking only** — no content-defined chunking, so any edit
  re-uploads downstream chunks (dedup/bandwidth cost).

## 3. Deliberately deferred (fine to defer, but they gate open-network scale)

Global anti-Sybil, Byzantine reputation, and payment/incentive layers are out of
scope by design. For a **trusted-operator / friends-and-family deployment** these
are acceptable; for an **open permissionless network** they are required, and
identity bans stay weak until then.

## 4. Ops and quality gaps

- `cmd/revika-node` now has **unit tests** (`main_test.go`, `logging_test.go`
  cover flag parsing, GC/repair/reprovide loops, and logging), but startup wiring
  is still exercised mainly through compose.
- **No benchmarks** anywhere → no performance/regression guardrails; only one fuzz
  target (`FuzzOpen` in `internal/crypto`).
- **Effectively Linux-only** today: `diskUsage` returns `ErrUnsupported` and
  `fsmeta` xattr/times are no-ops off Linux.
- No Makefile / systemd units / k8s manifests — deployment is docker-compose +
  shell scripts.
- Doc inconsistency to resolve: §3.2 lists quotas/leases as planned while §5/§3.4
  rely on them as implemented (they *are* implemented in `internal/ledger` and
  `internal/net`).

## Critical path

To reach production as the product described, in order:

1. ~~**Publish the signed root pointer over the DHT** (§4).~~ **Done.** The signed
   `RootPointer` is published as a DHT value record keyed by the owner's Ed25519
   pubkey (`/revika/<owner>`), guarded by a `record.Validator` that re-verifies the
   signature + owner-match and keeps the highest `Seq` (anti-rollback); it publishes
   only the **verify projection** (no read key), is refreshed by a 12h republish loop
   ahead of the DHT's 48h expiry, and is mirrored by a `/revika/root/1.0.0` node
   stream. `revika-ctl` publishes on every `cp`/`rm`/`revoke` commit (best-effort,
   behind the durable local `root.json`) and resolves by `ls -owner <pubkey>`.
2. ~~**Encrypt manifests/dirs and finish the read/write/verify cap chain with
   revocation.**~~ **Done.** Manifest/dir blobs are AES-256-GCM ciphertext; the
   write→read→verify cap chain and `revoke`-by-rekey ship (future-reads-only limit).
3. **Ship the sync daemon binary** (`cmd/revika-daemon`).
4. ~~**Write-verb rate limiting** (a `statusRateLimited` token bucket keyed on the
   owner) **+ harden the repair survival check against a lying `Store.Has`**.~~
   **Done (optional, off by default).** Per-owner write-rate limiting ships as
   `net.OwnerRateLimiter` (`-write-rate/-write-burst`); the repair check gains a
   proof-of-retrieval verify path (`-repair-verify`, `RepairStore.SetVerifyPossession`)
   that fetches + self-verifies a remote shard rather than trusting its presence byte.
   Both are local defences (never inherited). Rebalance already used the fresh-nonce
   `/revika/probe`; repair uses self-verifying fetch because the repairer lacks the
   shard bytes a probe response must be checked against.
5. **Client-side republish scheduling** (today a client only publishes synchronously
   on commit; a long-lived republish loop belongs to the sync daemon) and **multi-device
   write reconciliation** (§3.7).

Everything else — mount layer, anti-Sybil, payments, benchmarks, non-Linux
support — layers on after that.
