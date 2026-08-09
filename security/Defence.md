# Defence mechanisms – Revika

## Purpose

This document describes, **mechanism by mechanism**, the defences actually implemented
in revika and links each one to the attack scenarios of [`Security.md`](./Security.md).
This is the "by defence" view; the "by threat" view (one card per scenario, with the
detailed MITRE ATT&CK mapping) lives in the [`security/`](./README.md) tree, and the
canonical catalogue of defence *primitives* (P1–P27, with their D3FEND / NIST SP 800-53
correspondences) is in [`frameworks.md`](./frameworks.md). The three documents overlap:

- **Here**: how the mechanism works, where it lives in the code, what it covers.
- **`frameworks.md`**: which recognised frameworks each primitive `Pn` maps to.
- **`security/<ID>/README.md`**: the technique-by-technique ATT&CK detail of a scenario.

The layout follows the request: **first the node-side defences**, then **the client-side
defences**. The ordering follows *where the mechanism runs*. Recall the guiding principle
([Architecture.md](../Architecture.md), [CLAUDE.md](../CLAUDE.md)): **a node is a dumb,
untrusted blob store** — all intelligence (chunking, encryption, keys, sharing) is on the
client side; a node is never trusted for *confidentiality*, only for *availability*. Many
scenarios targeting nodes (`N-CONF-*`, `N-INT-STO-*`) are therefore neutralised by
mechanisms that run on the client side — they are covered in the client part and referred
to here by cross-reference.

> **Status.** Revika is in development. This document explicitly distinguishes what is
> **implemented** from what is **deferred** (global anti-Sybil, reputation, and economic
> incentive layers, corroborated distributed journal — cf. Architecture.md §5). The
> [Coverage and blind spots](#4-coverage-and-blind-spots) section recaps the scenarios not
> or partially covered, so as not to imply protection that does not exist.

---

# 1. Node-side defences

Mechanisms that run in the `revika-node` daemon (`cmd/revika-node`,
`internal/net`, `internal/ledger`, `internal/repair`). They protect the **availability**
of the node and the network, the **integrity** of shards at rest and on retrieval, and
the **admission** of writes — without ever decrypting or interpreting a shard.

## 1.1 Self-verifying content-address-hashed store — P4, P5

`internal/store` (`Store.Get` re-hashes the content and returns `ErrCorrupt` if the digest
does not match the `ShardID`; `ShardID = sha256`). On the network receive side, the server
(`internal/net/server.go`) and the client (`NetStore.putRaw`, `internal/net/client.go`)
verify that the announced CID matches the content actually stored/served. A shard is
therefore **unforgeable in place**: any alteration on disk breaks the CID↔content
correspondence and is detected on the next read, which triggers repair (§1.3).

- **Covered scenarios**: [N-INT-STO-01](./N-INT-STO-01/) (alteration of a shard),
  [N-INT-STO-02](./N-INT-STO-02/) (corrupted shard served),
  [N-INT-STO-04](./N-INT-STO-04/) (local reorganisation — the CID remains the address, the
  physical layout is irrelevant).

## 1.2 Proof of work at write admission — P9

`Server.enforcePoW` (`internal/net/server.go:164`) admits a PUT from a *fresh owner* only if
its Ed25519 signing key satisfies the local PoW difficulty (`-pow-difficulty`, Argon2id
puzzle, `internal/cap/pow.go`). The signing key is **self-certifying**: it is ground until
its pubkey hashes under the target, so that re-minting a banned identity costs CPU, not
milliseconds. The admission policy is propagated from the *seed* node to *joining* nodes via
`/revika/params` (`net.FetchNodePolicy`), the strictest value winning. Grant-authorized
maintenance flows (repair, rebalancing) and DELETEs are **exempt** — otherwise durability
would be taken hostage.

- **Covered scenarios**: [N-ORG-SYB-01](./N-ORG-SYB-01/) (creation of fake nodes —
  made costlier, not eliminated), [N-DISP-07](./N-DISP-07/) (saturation — PoW caps the
  admission rate of fresh load), [C-ECO-01](./C-ECO-01/)/[C-ECO-04](./C-ECO-04/) (mass
  creation of data / free resources, made costlier at admission).
- **Limitation**: banning by identity remains weak as long as identities are free to mint;
  PoW raises the cost, full P2P anti-Sybil is deferred (§5).

## 1.3 Erasure coding, repair and rebalancing — P6, P14, P16

Each file is Reed-Solomon erasure-coded (`internal/erasure`, `k=4`/`m=2` by default:
`k` data + `m` parity shards, any `k` reconstruct). `internal/repair` +
`internal/net/repair.go` (`RepairStore`) enumerate the ledger's stripes, probe shard
survival and **regenerate** those that are missing — since `erasure.Encode` is
**deterministic**, a regenerated shard reproduces its content address exactly, without ever
decrypting (repair on ciphertext, authorized by a signed *grant*, §1.7). Rebalancing
(`internal/net/rebalance.go`, pairwise diffusion §3.4) spreads the load in
**make-before-break** fashion and is never destructive before confirmation.

Two guards harden rebalancing, both independent of identity (hence tenable against Sybil):

- **`confirmStored`** (`rebalance.go:305`, GUARD1): challenges the peer to prove it holds
  *exactly* the shard (fresh nonce) **before** releasing the source copy (release
  probe-gated).
- **`peerStripeLoad`** (`rebalance.go:320`, GUARD2): caps concentration to ≤ `m`
  shards of the same stripe per node, so that no single node can, by dropping its copies,
  destroy a stripe.

- **Covered scenarios**: [N-DISP-01](./N-DISP-01/) (deletion of a shard: repair
  reconstitutes, the concentration guard limits a node's impact), [N-INT-STO-02](./N-INT-STO-02/)
  (corrupted shard: decode from the `k` healthy ones), [N-DISP-07](./N-DISP-07/)/[N-DISP-05](./N-DISP-05/)
  (saturation / partition: serve from other nodes), [N-ORG-SYB-02](./N-ORG-SYB-02/)
  (node collusion: the concentration guard bounds how much of the same stripe a colocated
  group holds).

## 1.4 Possession probes and challenges — P14

`ProbeProtocol` (`internal/net/proto.go`, `NonceSize=32`): the verifier sends a fresh
nonce, the holder must return `SHA256(nonce|shard)` in constant time
(`NetStore.Probe`). Impossible to answer without holding the shard, and impossible to replay
a response (single-use nonce). Two consumers:

- **`confirmStored`** in rebalancing (§1.3), which gates the release.
- **Possession verification in repair** (`RepairStore.SetVerifyPossession`,
  `-repair-verify`, `repair.go:65`): on demand, a shard's survival is no longer the
  mere `Store.Has` presence byte but a **proof of retrieval** (fetch +
  content-address self-verify), which catches a node that *lies* about what it
  holds.

- **Covered scenarios**: [N-INT-PRE-01](./N-INT-PRE-01/) (fake storage proofs),
  [N-INT-PRE-02](./N-INT-PRE-02/) (reuse of old proofs — fresh nonce),
  [N-INT-PRE-04](./N-INT-PRE-04/) (proof without data — the fetch reveals it),
  [N-INT-PRE-05](./N-INT-PRE-05/) (false availability), [N-DISP-08](./N-DISP-08/) (refusal of
  maintenance — a possession lie becomes a violation, §1.6).

## 1.5 Per-owner ledger: ownership, leases, quotas — P13

`internal/ledger` (SQLite `modernc.org/sqlite`, `.revika/ledger/ledger.db` — **not** a
blockchain) is the sole arbiter of a node's ownership and resources: tables
`shards`/`owners`/`accounts`/`stripes`, per-owner quotas (`QuotaBytes`), TTL leases
(`LeaseTTL`), GC of expired leases. The `Server` is **ledger-gated**: a fresh PUT is
refused if the owner exceeds its quota (`shard.put.rejected reason=quota`). Deduplication
by content address is counted by multi-owner refcount. The stripe row stores the
*grant* that authorizes maintenance moves without the User key (§1.7).

- **Covered scenarios**: [N-DISP-07](./N-DISP-07/) (saturation: the quota bounds the volume
  per owner), [C-ECO-01](./C-ECO-01/)/[C-ECO-02](./C-ECO-02/)/[C-ECO-03](./C-ECO-03/)
  (mass creation / multiplication / create-delete cycles, bounded by quota and leases),
  [C-DISP-04](./C-DISP-04/) (mass reconstruction requests, bounded by the owner's
  account).

## 1.6 Maintenance-abuse detector + persistent blocklist — P10, P11, P14

`internal/net/abuse.go` (`AbuseMonitor`) observes the two maintenance flows a peer
directs at this node and locally bans the abuser, acting **only** on
connection/identity metadata (never on content):

- **Too-fast rebalancing** (`ReasonRebalance`): sweeps arriving faster than
  `interval − tolerance`; one violation suffices (PUTs of the same sweep are coalesced).
- **Possession lies**: repeated fresh-nonce proof failures, counted as decaying *strikes*
  (default: 3 within a decay window).

A trailing `MoveReason` byte on `/revika/shard/1.2.0` distinguishes a policed
rebalance move from a schedule-exempt repair regeneration. Bans are
appended to a **runtime-mutable and persistent** blocklist (`net.Blocklister`,
`blocklist.auto`) that unions with the operator's static blocklist (`-blocklist`) and is
reloaded on restart. This anti-abuse tuning is a **local** defence, never inherited from
bootstrap nor ignored on a joining node.

- **Covered scenarios**: [N-DISP-04](./N-DISP-04/) (slowdown / cadence abuse),
  [N-DISP-08](./N-DISP-08/) (refusal of maintenance), [N-INT-PRE-01](./N-INT-PRE-01/)/[N-INT-PRE-04](./N-INT-PRE-04/)
  (possession lies sanctioned), [N-PROTO-02](./N-PROTO-02/)/[N-PROTO-03](./N-PROTO-03/)
  (malicious peers isolated by blocklist).

## 1.7 Signed repair grant + signed stripe descriptor — P20, P21

`internal/stripe`: `BuildGrant`/`VerifyGrant` (Ed25519 signature over `domain|expiry|desc`)
authorize a reconstruction move **on deterministic ciphertext** without ever
revealing the decryption key; the `Descriptor{K,M,Shards}` (non-confidential erasure
metadata, **no key**) is signed, so that a forgery invalidates the
signature. The node verifies the grant before accepting a maintenance PUT; this is what
distinguishes a legitimate maintenance write from an injection.

- **Covered scenarios**: [N-AC-02](./N-AC-02/) (granting access without authorization — a
  move without a valid grant is refused), [N-INT-MET-01](./N-INT-MET-01/) (falsification of
  erasure metadata).
- **Limitation**: grant expiry `0` = never, grant revocation is **TODO**
  (`internal/stripe`).

## 1.8 Per-owner write rate limiting — P10

`internal/net/ratelimit.go` (`OwnerRateLimiter`): per-owner token bucket (key = Ed25519
pubkey recovered from the auth token) refusing PUT/DELETE beyond `-write-rate` /
`-write-burst` with `statusRateLimited` (`proto.go:99`). This is the **rate cap** that
complements the storage quota (the *volume* cap, §1.5). Grant-authorized maintenance
writes are exempt. Optional, disabled by default; a local defence.

- **Covered scenarios**: [N-DISP-07](./N-DISP-07/) (saturation by write flood),
  [C-DISP-01](./C-DISP-01/) (flood), [C-DISP-02](./C-DISP-02/) (request multiplication),
  [C-ECO-02](./C-ECO-02/) (operation multiplication).
- **Limitation**: rate limiting of **read** verbs (`GET`/`HAS`/`PROBE`) is **TODO**.

## 1.9 Network bounding: ConnectionGater / ResourceManager / ConnManager — P11

`internal/net/defense.go` (`DefenseConfig`, wired via `HostConfig.Defense`): the
libp2p `ResourceManager` and `ConnManager` bound connections and resources
(`-conn-low`/`-conn-high`/`-conn-grace`); the `ConnectionGater` applies a peer /
subnet blocklist (`LoadBlocklistFile`/`ParseBlocklist`), fed statically and by the
abuse detector (§1.6). This is the *flow/connection* cap (as opposed to the ledger's
storage cap).

- **Covered scenarios**: [N-DISP-07](./N-DISP-07/) (CPU/memory/bandwidth saturation),
  [N-DISP-03](./N-DISP-03/) (refusal to respond imposed on unwanted peers),
  [N-PROTO-02](./N-PROTO-02/) (Eclipse: connection diversity + blocklist),
  [C-DISP-02](./C-DISP-02/) (connection multiplication).

## 1.10 Private DHT discovery + authenticated libp2p transport — P15, P17

Kademlia discovery on a private `/revika` prefix (`internal/net/dht.go`, `Discovery`): the
location of a shard is a *provider record*, not a hash ring; a move =
a re-announce, and DHT redundancy avoids the single point. The libp2p transport is
**end-to-end encrypted and authenticated** (peer identity = libp2p key), so that a
peer is authenticated before any exchange and traffic is confidential in transit.

- **Covered scenarios**: [N-PROTO-03](./N-PROTO-03/) (redirection to fake peers:
  authenticated peers), [N-CONF-04](./N-CONF-04/) (flow observation: encrypted transport),
  [N-DISP-05](./N-DISP-05/) (partition: redundant discovery),
  [N-AC-05](./N-AC-05/)/[C-AC-03](./C-AC-03/) (forging a requester's identity: authenticated
  peer identity + signed token).

## 1.11 Fail-closed versioned protocols — P18

A single version per stream protocol (`ShardProtocol`, `ProbeProtocol`, … in
`proto.go`) is registered and offered; the libp2p muxer **fails negotiation** against a
mismatched peer rather than mis-framing a frame. The version ID is bumped when the
frame changes, without keeping the predecessor around (no back-compat in dev). The served
versions are advertised at startup and on `/status` + `/metrics` (`internal/net/metrics.go`).

- **Covered scenarios**: [N-PROTO-05](./N-PROTO-05/) (exploitation of vulnerabilities:
  reduced surface, strictly validated inputs), [N-PROTO-06](./N-PROTO-06/) (disabling
  of checks: the non-conforming peer fails negotiation),
  [C-PROTO-02](./C-PROTO-02/) (invalid order), [C-PROTO-03](./C-PROTO-03/) (old protocol
  version: refused), [C-PROTO-04](./C-PROTO-04/) (undefined behaviours).

## 1.12 "Dumb / untrusted node" principle — P23 (and provenance P26)

The node is designed to deserve no confidentiality trust: it sees only
self-verifying CID-addressed ciphertext (§1.1), all decisive re-verification takes place
on the User side (§2). Security **does not depend** on the node behaving well. The build
chain stays pure-Go, cgo-free, with a pinned toolchain (`go 1.26`) and vendored dependencies — for
provenance (P26).

- **Covered scenarios** (as an underlying engineering principle): the whole of the
  `N-CONF-*` and `N-INT-STO-*` (see §2.1–§2.3 for the client mechanisms that
  neutralise them), [N-PROTO-04](./N-PROTO-04/) (modified software: a modified node gains
  no access to plaintext or keys).

---

# 2. Client-side defences

Mechanisms that run on the User side (`cmd/revika-ctl`, `internal/crypto`, `internal/cap`,
`internal/manifest`, `internal/device`, `internal/provider`). They protect the
**confidentiality** and **integrity** of the user's data *despite* untrusted nodes,
as well as **access control** (sharing, revocation, devices). This is where
most `N-CONF-*` and `N-INT-STO-*` scenarios are neutralised: they *target* the
nodes but are *defeated* by client code.

## 2.1 Client-side AES-256-GCM encryption — P1

`internal/crypto` (`Key`, `Seal`, `Open`, AES-256-GCM, AEAD, non-deterministic seal). **Everything
is encrypted on the client side before the slightest shard leaves the machine** (pipeline
`chunk → compress → encrypt → erasure`, `internal/pipeline`). A node stores only opaque
ciphertext; no key ever reaches a node.

- **Covered scenarios**: [N-CONF-01](./N-CONF-01/) (unauthorized reading of shards),
  [N-CONF-02](./N-CONF-02/)/[N-CONF-03](./N-CONF-03/) (access analysis / metadata
  correlation — the content stays opaque), [C-CONF-01](./C-CONF-01/) (inferring the existence of
  data — mitigated, cf. §2.10).

## 2.2 ML-KEM-768 capability wrapping — P2

`internal/cap` (`Wrap`/`Unwrap`, ML-KEM-768 as KEM-DEM + AES-256-GCM, PQC) and
`internal/manifest` (`WrapCap`/`UnwrapCap`). **Sharing = key wrapping**, never
a copy of plaintext: a read-capability (manifest location + decryption key)
is wrapped to the recipient's ML-KEM pubkey. `share rvk:PATH -to <pubkey-file>`
seals a `RootPointer` anchored at the subtree to the recipient's key — a *sealed shared
root*, **never a bearer token**. Pubkeys are always passed as **files**,
never in the clear on the command line.

- **Covered scenarios**: [C-AC-01](./C-AC-01/) (access without authorization: without the
  ML-KEM private key, nothing decrypts), [C-AC-06](./C-AC-06/) (sharing of rights: a cap is
  sealed to a recipient, not a replayable secret), [N-CONF-01](./N-CONF-01/) (the key stays
  on the User side).

## 2.3 Content-address re-verification on retrieval — P5, P19

On download, the client re-hashes each shard (`store.Get` → `ErrCorrupt`), and
`NetStore.putRaw` verifies that the node did echo back the exact CID at storage. The mutable
root is a **Ed25519-signed and versioned** `manifest.RootPointer` (`SignRoot`, monotone
`Seq`), persisted via `provider.FileRootStore` (`root.json`, **anti-rollback**: refuses a
lower `Seq`). A node can therefore neither corrupt a shard without being detected, nor
re-serve an **old** root without the version number giving it away.

- **Covered scenarios**: [N-INT-STO-01](./N-INT-STO-01/) (alteration detected),
  [N-INT-STO-02](./N-INT-STO-02/) (corruption detected + decode from the healthy ones),
  [N-INT-STO-03](./N-INT-STO-03/) (rollback: monotone `Seq` + local anti-rollback),
  [C-INT-DAT-01](./C-INT-DAT-01/) (corrupted data rejected),
  [C-INT-MET-04](./C-INT-MET-04/) (version manipulation),
  [N-INT-MET-02](./N-INT-MET-02/) (timestamps are not trusted: order is
  carried by signed `Seq`).

## 2.4 Distributed placement on independent owners + tolerant decoding — P6, P16

`internal/placement` (`Selector` round-robin / weighted, `Spread` by failure domain)
spreads the shards of a stripe over **distinct** nodes/pubkeys: no subset
< `k` reconstitutes the file, and any `k` out of `k+m` suffice to decode
(`erasure.Decode`). The client therefore tolerates a node that withholds, corrupts or
disappears, as long as `k` healthy shards remain reachable.

- **Covered scenarios**: [N-DISP-01](./N-DISP-01/)/[N-DISP-02](./N-DISP-02/)/[N-DISP-03](./N-DISP-03/)
  (deletion / refusal to provide / refusal to respond: decode from the others),
  [N-CONF-01](./N-CONF-01/) (confidentiality by fragmentation: a node never holds a
  whole file), [N-ORG-SYB-04](./N-ORG-SYB-04/)/[N-ORG-GEO-03](./N-ORG-GEO-03/)
  (concentration: the spread by failure domain counters it — see limitations §5).

## 2.5 Self-certifying Ed25519 signing identity — P3, P9

`internal/cap` (`SignKey`/`SignPubKey`, `MintSigningKey`, `MeetsPoW`). The storage owner
identity is an Ed25519 key **ground by PoW** (`-pow-difficulty`, default
12): its pubkey hashes under a target, so re-minting an identity costs CPU. All
tokens and capabilities are Ed25519-signed; any invalid signature is rejected, forgery
requiring the private key.

- **Covered scenarios**: [C-AC-03](./C-AC-03/) (forged token rejected),
  [C-INT-SIG-02](./C-INT-SIG-02/) (signature of different content: the signature covers the
  content), [N-INT-ID-01](./N-INT-ID-01/) (identity spoofing),
  [N-AC-05](./N-AC-05/) (forging a requester's identity),
  [C-INT-MET-03](./C-INT-MET-03/) (false origin: the origin is the signing pubkey).

## 2.6 Anti-replay: nonce, TTL, seq — P8

Fresh single-use nonce in possession challenges (`NonceSize=32`, §1.4), monotone
signed `Seq` on roots (§2.3), TTL leases on the ledger side (§1.5). A response, a root
or a right cannot be **replayed** outside its window.

- **Covered scenarios**: [C-INT-SIG-03](./C-INT-SIG-03/) (signature replay),
  [N-INT-PRE-02](./N-INT-PRE-02/) (reuse of old proofs),
  [N-INT-REG-05](./N-INT-REG-05/) (event replay — for the part covered by `Seq`),
  [C-AC-02](./C-AC-02/) (reuse of an expired right, via TTL).

## 2.7 Revocable capabilities: forward re-keying — P12

`revoke rvk:PATH` (`manifest.Rekey`) re-keys the subtree down to its data chunks, advances +
republishes the root, and reclaims the orphaned shards: a previously shared capability
**can no longer read the current bytes** (*forward-only* revocation — copies already
downloaded cannot be clawed back). This is a revocation by re-encryption, not by
node-side authorization.

- **Covered scenarios**: [C-AC-05](./C-AC-05/) (revocation bypass: the new
  bytes are under a new key), [N-AC-01](./N-AC-01/) (ignoring a revocation: the node
  has nothing to enforce — the revocation is cryptographic),
  [N-AC-03](./N-AC-03/)/[N-AC-04](./N-AC-04/) (serving after expiry / stale
  permissions: without re-key, a revoked cap no longer decrypts).
- **Limitation**: node-enforced **write** revocation is **deferred**; only
  read revocation is cryptographically forced.

## 2.8 Revocable device model under the master credential — P3, P12

`internal/device` (`Auth` = set signed by the master key of the ML-KEM device pubkeys,
`devices.json`, DHT mirror `/revika-devices/<owner>`). The User is a *principal* whose
**master credential** (offline owner Ed25519 key) enrolls/revokes individually-keyed
*devices*. `device revoke` advances the signed set and **reseals the root companion
to exactly the surviving devices** (`manifest.SealFullRootFor` →
`FullRootRecord.Seals`): a revoked device's key no longer opens any current companion
(`manifest.ErrNoSealForKey`).

- **Covered scenarios**: [C-INT-SIG-04](./C-INT-SIG-04/) (stolen signature / compromised
  device: revocable), [C-INT-SIG-05](./C-INT-SIG-05/) (compromised key),
  [C-AC-04](./C-AC-04/) (privilege escalation: the device set is signed by the
  offline master), [N-INT-ID-03](./N-INT-ID-03/) (device key theft, bounded blast radius).
- **Limitation**: forward-only read revocation (already-downloaded plaintext not clawable back).

## 2.9 Multi-device commit: lossless merge-publish — P7 (partial), P19

`commitRoot` (`cmd/revika-ctl`) is a **read-merge-publish** loop: each commit reads the
current DHT root, compares it to the merge base (the durable local `root.json`), does a
three-way merge (`manifest.Merge3`) on divergence — conflicting
leaves become **device-tagged conflict copies** (`Config.DeviceTag`), never silent
losses — signs at `max(local,remote).Seq+1`, and re-reads to catch a concurrent writer.
`rootValidator.Select` breaks an equal-`Seq` fork by total byte order (not
first-seen), so that replicas **converge**. The decryptable root reaches the other
devices via the *sealed self-root companion* (`manifest.FullRootRecord`, DHT
`/revika-fullcap/<owner>`), the public root staying key-stripped.

- **Covered scenarios**: [C-INT-DAT-03](./C-INT-DAT-03/) (incompatible versions:
  reconciled, not lost), [N-INT-REG-01](./N-INT-REG-01/) (double publication: deterministic
  `Select` converges), [C-COL-04](./C-COL-04/)/[N-INT-REG-04](./N-INT-REG-04/) (coordinated
  fake events: only roots signed by the owner are retained).
- **Limitation**: this is not a corroborated distributed journal (P27, full P7) — see §5.

## 2.10 Normalisation: fixed-size chunking + key isolation — P25, P24

Fixed-size chunking (`internal/chunk`) and per-chunk compression only when it wins
(`internal/compress`): shards are **normalised**, which limits size-based correlation
analysis. The User keys (ML-KEM + Ed25519 signature) live only under
`.revika/keys` (git-ignored), **never transmitted off-machine**, with restricted
permissions (P24).

- **Covered scenarios**: [N-CONF-03](./N-CONF-03/)/[N-CONF-05](./N-CONF-05/) (metadata
  correlation / relationship inference: mitigated by normalisation),
  [C-CONF-01](./C-CONF-01/) (existence inference: mitigated),
  [N-INT-ID-03](./N-INT-ID-03/)/[C-INT-SIG-04](./C-INT-SIG-04/) (key theft: isolation
  reduces the surface).
- **Limitation**: fixed-size chunking (CDC planned) and normalisation do not eliminate
  fine-grained traffic analysis; response-time observation ([C-CONF-03](./C-CONF-03/),
  [N-CONF-02](./N-CONF-02/)) remains partially exposed.

## 2.11 Verify-only inspection of a published root — P19

`ls -owner <pubkey-file>` resolves a namespace's published DHT root **only in its
verify-cap form** (shard locations + integrity, **no decryption**): it is an
inspector of liveness/revocation, not a browse path. The public root stays
key-stripped (§2.9). No read key is exposed by this path.

- **Covered scenarios**: [C-AC-01](./C-AC-01/) (inspect without reading),
  [N-CONF-01](./N-CONF-01/) (the public path leaks no key).

---

# 3. Shared defences (node ⇄ client)

- **Encrypted/authenticated libp2p transport — P17** (§1.10): protects every exchange in both
  directions ([N-CONF-04](./N-CONF-04/), [C-CONF-02](./C-CONF-02/)).
- **Signed grants — P20** (§1.7): issued on the client side, verified on the node side.
- **Content addressing — P4/P5** (§1.1, §2.3): self-verification at both ends.

---

# 4. Coverage and blind spots

Synthetic scenario → main defence mapping. `✔` implemented, `~` partial/mitigated,
`✗` deferred (see §5).

## 4.1 Scenarios targeting nodes

| Scenario | Main defence | Status |
| --- | --- | --- |
| [N-CONF-01](./N-CONF-01/) Shard reading | P1 encryption + P6/P16 fragmentation (§2.1, §2.4) | ✔ |
| [N-CONF-02](./N-CONF-02/) Access analysis | P25 normalisation (§2.10) | ~ |
| [N-CONF-03](./N-CONF-03/) Metadata correlation | P1 + P25 (§2.1, §2.10) | ~ |
| [N-CONF-04](./N-CONF-04/) Flow observation | P17 encrypted transport (§1.10) | ✔ |
| [N-CONF-05](./N-CONF-05/) Relationship inference | P25 normalisation (§2.10) | ~ |
| [N-INT-STO-01](./N-INT-STO-01/) Shard alteration | P4/P5 (§1.1, §2.3) | ✔ |
| [N-INT-STO-02](./N-INT-STO-02/) Corrupted shard | P5 + P6 decoding (§2.3, §1.3) | ✔ |
| [N-INT-STO-03](./N-INT-STO-03/) Rollback | P19 `Seq` + anti-rollback (§2.3) | ✔ |
| [N-INT-STO-04](./N-INT-STO-04/) Local reorg | P4 content addressing (§1.1) | ✔ |
| [N-INT-MET-01](./N-INT-MET-01/) Metadata falsification | P21 signed descriptor (§1.7) | ✔ |
| [N-INT-MET-02](./N-INT-MET-02/) Timestamps | P19 signed `Seq` replaces the clock (§2.3) | ✔ |
| [N-INT-MET-03](./N-INT-MET-03/) History rewriting | P7/P27 corroborated journal | ✗ |
| [N-INT-MET-04](./N-INT-MET-04/) Event deletion | P27 inter-peer corroboration | ✗ |
| [N-INT-REG-01](./N-INT-REG-01/) Double publication | P19 deterministic `Select` (§2.9) | ✔ |
| [N-INT-REG-02..03](./N-INT-REG-02/) Registry rewriting/omission | P7/P27 | ✗ |
| [N-INT-REG-04](./N-INT-REG-04/) Fictitious events | P3 signatures (§2.9) | ~ |
| [N-INT-REG-05](./N-INT-REG-05/) Event replay | P8 (§2.6) | ~ |
| [N-INT-PRE-01](./N-INT-PRE-01/) Fake storage proofs | P14 + repair-verify (§1.4) | ✔ |
| [N-INT-PRE-02](./N-INT-PRE-02/) Proof reuse | P8 fresh nonce (§1.4, §2.6) | ✔ |
| [N-INT-PRE-03](./N-INT-PRE-03/) Proof mutualisation | P14 per-shard challenge | ~ |
| [N-INT-PRE-04](./N-INT-PRE-04/) Proof without data | P14 proof-of-retrieval (§1.4) | ✔ |
| [N-INT-PRE-05](./N-INT-PRE-05/) False availability | P14 (§1.4) | ✔ |
| [N-INT-ID-01](./N-INT-ID-01/) Spoofing | P3/P9 self-certifying identity (§2.5) | ✔ |
| [N-INT-ID-02](./N-INT-ID-02/) Identity duplication | P9 PoW (§1.2, §2.5) | ~ |
| [N-INT-ID-03](./N-INT-ID-03/) Private key theft | P24 isolation + P12 revocation (§2.8, §2.10) | ~ |
| [N-DISP-01](./N-DISP-01/) Shard deletion | P6 repair + GUARD2 (§1.3) | ✔ |
| [N-DISP-02..03](./N-DISP-02/) Refusal to provide/respond | P6/P16 decode elsewhere (§2.4) | ✔ |
| [N-DISP-04](./N-DISP-04/) Slowdown | P10 + AbuseMonitor (§1.6, §1.8) | ~ |
| [N-DISP-05](./N-DISP-05/) Partition | P15 DHT + P6 (§1.10, §1.3) | ~ |
| [N-DISP-06](./N-DISP-06/) Gossip blocking | n/a (revika = DHT, no gossip) | ~ |
| [N-DISP-07](./N-DISP-07/) Saturation | P9/P10/P11/P13 (§1.2, §1.8, §1.9, §1.5) | ✔ |
| [N-DISP-08](./N-DISP-08/) Maintenance refusal | P14 + AbuseMonitor (§1.4, §1.6) | ✔ |
| [N-DISP-09](./N-DISP-09/) Strategic disconnection | P6 repair + P14 (§1.3, §1.4) | ~ |
| [N-AC-01](./N-AC-01/) Ignoring revocation | P12 cryptographic re-key (§2.7) | ✔ |
| [N-AC-02](./N-AC-02/) Access without authorization | P20 signed grant (§1.7) | ✔ |
| [N-AC-03..04](./N-AC-03/) After expiry / stale | P12 + P8 TTL (§2.7, §2.6) | ~ |
| [N-AC-05](./N-AC-05/) Requester forgery | P3 + P17 authenticated peer (§2.5, §1.10) | ✔ |
| [N-PROTO-01](./N-PROTO-01/) Fake Gossip | n/a (DHT; injection = signed record required) | ~ |
| [N-PROTO-02](./N-PROTO-02/) Eclipse | P11 + P15 diversity (§1.9, §1.10) | ~ |
| [N-PROTO-03](./N-PROTO-03/) Fake peers | P17 authentication (§1.10) | ✔ |
| [N-PROTO-04](./N-PROTO-04/) Modified software | P23 untrusted node (§1.12) | ✔ |
| [N-PROTO-05](./N-PROTO-05/) Vulnerabilities | P18 fail-closed (§1.11) | ~ |
| [N-PROTO-06](./N-PROTO-06/) Disabling checks | P18 + P23 User re-verification (§1.11, §1.12) | ✔ |
| [N-ECO-01..04](./N-ECO-01/) Economic threats | incentive layer | ✗ |
| [N-ORG-SYB-01](./N-ORG-SYB-01/) Fake nodes | P9 PoW (§1.2) | ~ |
| [N-ORG-SYB-02](./N-ORG-SYB-02/) Node collusion | P16/GUARD2 concentration (§1.3, §2.4) | ~ |
| [N-ORG-SYB-03..04](./N-ORG-SYB-03/) Censorship/regional majority | anti-Sybil + reputation | ✗ |
| [N-ORG-GEO-01..04](./N-ORG-GEO-01/) Geolocation | P22 measured diversity (partial) | ✗ |

## 4.2 Scenarios targeting clients

| Scenario | Main defence | Status |
| --- | --- | --- |
| [C-CONF-01](./C-CONF-01/) Data existence | P1 + P25 (§2.1, §2.10) | ~ |
| [C-CONF-02](./C-CONF-02/) Metadata correlation | P17 + P25 (§1.10, §2.10) | ~ |
| [C-CONF-03](./C-CONF-03/) Response time | — | ✗ |
| [C-CONF-04](./C-CONF-04/) Public info | P19 verify-only cap (§2.11) | ~ |
| [C-INT-DAT-01](./C-INT-DAT-01/) Corrupted data | P5 re-verification (§2.3) | ✔ |
| [C-INT-DAT-02](./C-INT-DAT-02/) Unauthorized modification | P3/P19 signed root (§2.3, §2.5) | ✔ |
| [C-INT-DAT-03](./C-INT-DAT-03/) Incompatible versions | P19 merge3 (§2.9) | ✔ |
| [C-INT-DAT-04](./C-INT-DAT-04/) Logical deletion | P19 `Seq` + P6 repair | ~ |
| [C-INT-DAT-05](./C-INT-DAT-05/) Malicious injection | P3 owner signature (§2.5) | ✔ |
| [C-INT-MET-01](./C-INT-MET-01/) Falsification | P19 signed manifest (§2.3) | ✔ |
| [C-INT-MET-02](./C-INT-MET-02/) Timestamps | P19 `Seq` (§2.3) | ✔ |
| [C-INT-MET-03](./C-INT-MET-03/) False origin | P3 signing pubkey (§2.5) | ✔ |
| [C-INT-MET-04](./C-INT-MET-04/) Version manipulation | P19 anti-rollback (§2.3) | ✔ |
| [C-INT-MET-05](./C-INT-MET-05/) Fake recipient list | P2 per-device seals (§2.2, §2.8) | ✔ |
| [C-INT-SIG-01](./C-INT-SIG-01/) Double signature | P3 + P19 `Select` (§2.9) | ~ |
| [C-INT-SIG-02](./C-INT-SIG-02/) Different content | P3 (§2.5) | ✔ |
| [C-INT-SIG-03](./C-INT-SIG-03/) Replay | P8 (§2.6) | ✔ |
| [C-INT-SIG-04](./C-INT-SIG-04/) Stolen signature | P12 device revocation (§2.8) | ✔ |
| [C-INT-SIG-05](./C-INT-SIG-05/) Compromised key | P12 revocation (§2.8) | ✔ |
| [C-INT-JRN-01..04](./C-INT-JRN-01/) Journals | P7/P27 corroborated journal | ✗ |
| [C-DISP-01](./C-DISP-01/) Flood | P10 (§1.8) | ✔ |
| [C-DISP-02](./C-DISP-02/) Connection multiplication | P11 (§1.9) | ✔ |
| [C-DISP-03](./C-DISP-03/) Interrupted downloads | P6 idempotent + P4 (§1.3) | ~ |
| [C-DISP-04](./C-DISP-04/) Mass reconstructions | P13 quotas (§1.5) | ~ |
| [C-DISP-05](./C-DISP-05/) Verification saturation | P10/P11 (§1.8, §1.9) | ~ |
| [C-AC-01](./C-AC-01/) Access without authorization | P2 sealed cap (§2.2) | ✔ |
| [C-AC-02](./C-AC-02/) Expired right | P8 TTL (§2.6) | ~ |
| [C-AC-03](./C-AC-03/) Forged token | P3 (§2.5) | ✔ |
| [C-AC-04](./C-AC-04/) Privilege escalation | P3/P12 master credential (§2.8) | ✔ |
| [C-AC-05](./C-AC-05/) Revocation bypass | P12 re-key (§2.7) | ✔ |
| [C-AC-06](./C-AC-06/) Sharing of rights | P2 non-bearer cap (§2.2) | ~ |
| [C-PROTO-01..04](./C-PROTO-01/) Protocol | P18 fail-closed (§1.11) | ✔ |
| [C-PROTO-05](./C-PROTO-05/) Fake capabilities | P14 probes (§1.4) | ~ |
| [C-ECO-01](./C-ECO-01/) Mass creation | P9 + P13 (§1.2, §1.5) | ~ |
| [C-ECO-02](./C-ECO-02/) Operation multiplication | P10 (§1.8) | ~ |
| [C-ECO-03](./C-ECO-03/) Create/delete cycles | P13 leases/quotas (§1.5) | ~ |
| [C-ECO-04](./C-ECO-04/) Free resources | P9 PoW (§1.2) | ~ |
| [C-COL-01..02](./C-COL-01/) Client/node collusion | P16 + reputation | ~ |
| [C-COL-03](./C-COL-03/) Key sharing | P12 revocation (§2.7, §2.8) | ~ |
| [C-COL-04](./C-COL-04/) Coordinated fake events | P3/P19 (§2.9) | ~ |

---

# 5. Assumed blind spots (deferred)

Consistent with Architecture.md §5 and [`frameworks.md`](./frameworks.md#accepted-blind-spots):

- **Corroborated distributed journal (full P7, P27)** — the revika ledger is per-node, local
  SQLite; there is no replicated, inter-peer corroborated append-only journal. The
  scenarios of history rewriting/omission and audit
  ([N-INT-MET-03/04](./N-INT-MET-03/), [N-INT-REG-02/03](./N-INT-REG-02/),
  [C-INT-JRN-01..04](./C-INT-JRN-01/)) remain **uncovered**.
- **Global anti-Sybil, reputation, economic incentives** — PoW makes identity creation
  costlier but does not eliminate it; there is no reputation or payment layer.
  [N-ECO-*](./N-ECO-01/), [C-ECO-*](./C-ECO-01/), [N-ORG-SYB-03/04](./N-ORG-SYB-03/),
  [C-COL-01/02](./C-COL-01/) remain **partial or deferred**.
- **Verifiable geolocation (P22)** — placement diversity measured by the network
  (observed RTT/AS) is planned but not enforcing; [N-ORG-GEO-*](./N-ORG-GEO-01/) is
  **deferred**. The current `geoip` (`internal/geoip`) serves the `/admin` dashboard map, not
  a proof of location.
- **Read rate limiting** — `GET`/`HAS`/`PROBE` are not yet capped;
  [C-DISP-05](./C-DISP-05/), [C-CONF-03](./C-CONF-03/) remain partially exposed.
- **Node-enforced write revocation** — only **read** revocation is
  cryptographically forced (re-key, §2.7); node-side write revocation is deferred.
- **Grant revocation** — expiry `0` = never; grant revocation is **TODO**
  (`internal/stripe`).
- **No gossip layer** — revika discovers via DHT; the scenarios framed in terms of
  gossip ([N-PROTO-01](./N-PROTO-01/), [N-DISP-06](./N-DISP-06/)) are re-interpreted onto the
  DHT (a record must be signed to be retained; blocking propagation amounts to a
  partition, mitigated by DHT redundancy).

---

## See also

- [`Security.md`](./Security.md) — catalogue of attack scenarios (source of the IDs).
- [`README.md`](./README.md) — index of the per-scenario cards.
- [`frameworks.md`](./frameworks.md) — catalogue of primitives P1–P27 and D3FEND / NIST mappings.
- [`../Architecture.md`](../Architecture.md) — detailed design and deferred layers (§5).
- [`../CLAUDE.md`](../CLAUDE.md) — guiding principles and design constraints.
