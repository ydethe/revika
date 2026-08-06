# Production readiness

Status snapshot: **2026-08-06.** What separates today's tree from a production
self-hosted Drive. See [Architecture.md](../Architecture.md) for the full design;
this file only tracks the gaps.

The engineering baseline is strong for the current stage: a green `go test -race`
suite, multi-node/resilience/repair end-to-end jobs in CI, multi-arch image
publishing, `/healthz` `/readyz` `/status` `/metrics` endpoints, and structured
`slog` logging. The gaps below are at three levels — architectural blockers first,
then hardening the design already calls for, then deferred layers and ops polish.

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

- **Write-verb rate limiting is still TODO** (per-owner / per-peer token bucket on
  PUT/DELETE). Connection/rcmgr defenses exist (`internal/net/defense.go`);
  flow control on writes does not.
- **PoW difficulty advertisement** (`/revika/params`) — clients discover a node's
  difficulty via a late auth failure instead of up front.
- **Repair still probes with `Store.Has`, not the `/revika/probe`
  proof-of-possession** — a lying node defeats the availability check.
  Repair-onto-fresh-nodes and repair cadence/threshold policy are open.
- **Placement diversity not enforced**: the failure-domain `Spread` invariant isn't
  applied on moves, capacity (`LoadReport`) is self-declared and untrusted, and the
  per-shard cooldown is in-memory (lost on restart).
- **Fixed-size chunking only** — no content-defined chunking, so any edit
  re-uploads downstream chunks (dedup/bandwidth cost).

## 3. Deliberately deferred (fine to defer, but they gate open-network scale)

Global anti-Sybil, Byzantine reputation, and payment/incentive layers are out of
scope by design. For a **trusted-operator / friends-and-family deployment** these
are acceptable; for an **open permissionless network** they are required, and
identity bans stay weak until then.

## 4. Ops and quality gaps

- `cmd/revika-node` (the daemon binary) has **no unit tests** — startup/wiring is
  only covered indirectly via compose.
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
4. **Write-verb rate limiting + proof-of-possession repair.**
5. **Client-side republish scheduling** (today a client only publishes synchronously
   on commit; a long-lived republish loop belongs to the sync daemon) and **multi-device
   write reconciliation** (§3.7).

Everything else — mount layer, anti-Sybil, payments, benchmarks, non-Linux
support — layers on after that.
