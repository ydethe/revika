# Operations guide — revika node

Audience: operators running one or more `revika-node` instances in a trusted-operator or
friends-and-family deployment. For the full architectural rationale see
[Architecture.md](../Architecture.md); for the threat-model catalogue see
[security/Security.md](../security/Security.md).

---

## 1. Security posture

**Nodes are intentionally dumb and untrusted.** They store opaque, content-addressed
ciphertext shards. They are trusted for *availability*, never for *confidentiality*.
Concretely:

- **All encryption is client-side.** A node never sees a decryption key. A compromised
  node loses availability for its shards, not the confidentiality of any file — other
  nodes hold different shards; erasure coding reconstructs the file from any `k`-of-`k+m`.
- **Read verbs (`GET`/`HAS`) carry no authorization check by design.** Any peer that
  knows a shard's content-address hash can fetch it. Confidentiality therefore rests on
  two properties: (a) AES-256-GCM encryption, and (b) *shard-ID secrecy* — the hash is
  not public; it is derived from the plaintext content and is disclosed only inside a
  read-capability sealed to the recipient's ML-KEM public key. Treat shard IDs as secrets:
  **do not publish shard IDs or share root files over unencrypted channels.**
- **Write verbs (`PUT`/`DELETE`) require a signed auth token** from the storage owner
  (Ed25519). A node that forges or replays such a token is caught by the signature check.
- **Discovery is DHT-only** (Kademlia on the `/revika` private prefix). There is no
  mDNS or LAN auto-discovery; all peers are explicitly bootstrapped.
- **Repair operates on ciphertext only.** A node regenerates missing shards from the
  parity shards it holds without ever holding or needing a decryption key. The
  authorization for a repair move is a signed *grant* (`internal/stripe`).

### What this deployment is not (current limits)

This is a development-grade, trusted-operator deployment. The following are deferred:

- Global anti-Sybil / identity reputation / economic incentives.
- Node-enforced write revocation (read revocation via re-keying works; see `revika-ctl revoke`).
- Repair grant revocation (grants have no default expiry — see issue #12).
- Read-verb per-owner rate limiting (subnet rate cap is on by default as a DoS backstop).
- Corroborated distributed audit journal.

---

## 2. First-time setup

### Prerequisites

- Linux host (the node is Linux-only today; `diskUsage` and `fsmeta` return
  `ErrUnsupported` on other platforms).
- Go 1.26+ or Docker.
- `GOTOOLCHAIN=auto` in the environment (Go 1.26 is fetched automatically if the system
  Go is older).

### Build from source

```bash
git clone https://github.com/ydethe/revika
cd revika
go build -o revika-node ./cmd/revika-node
go build -o revika-ctl  ./cmd/revika-ctl
```

### Docker image

```bash
docker build -t revika-node .              # or pull a published image
```

### Mint the node identity

A node with no key at `<data>/keys/node.key` self-generates a fresh Ed25519 identity on
first boot and writes it to `0600`. This is the recommended path — no pre-generated key
needed. The Peer ID is printed on startup.

To pin the Peer ID before starting (e.g. so other nodes can bootstrap through this one
before it is up), mint the key ahead of time:

```bash
./revika-ctl nodekey -o /var/lib/revika/keys/node.key
# prints: Peer ID: 12D3KooW…
```

### Mint a user identity

```bash
./revika-ctl keygen                        # writes .revika/keys/user.{key,pub,sign.key,sign.pub}
```

---

## 3. Running a single node

```bash
./revika-node \
  -data      /var/lib/revika \
  -listen    /ip4/0.0.0.0/tcp/4001 \
  -listen    /ip4/0.0.0.0/udp/4001/quic-v1 \
  -public-ip <your-public-ip> \            # omit if behind a NAT you won't traverse
  -metrics   :9096                         # exposes /healthz /readyz /status /metrics /admin
```

The node announces its dialable multiaddrs on startup. Copy the `/ip4/…/tcp/…/p2p/…`
address; other nodes and clients pass it as `-bootstrap`.

### Running with Docker

```bash
docker run -d --name revika-node \
  -p 4001:4001 -p 4001:4001/udp \
  -v revika-data:/data \
  revika-node \
  -data /data -public-ip <your-public-ip>
```

---

## 4. Running a cluster

Pick one machine as the **seed** node (no `-bootstrap`). It states the cluster-wide
policy: admission PoW difficulty, repair/rebalance cadence.

```bash
# seed — policy flags set here; joiners inherit them
./revika-node -data /var/lib/revika-seed \
  -listen /ip4/0.0.0.0/tcp/4001 \
  -listen /ip4/0.0.0.0/udp/4001/quic-v1 \
  -public-ip <seed-public-ip> \
  -pow-difficulty 12 \
  -repair-interval 1h \
  -rebalance-interval 1h

# joining nodes — inherit the seed's policy; only -bootstrap is required
./revika-node -data /var/lib/revika-node2 \
  -listen /ip4/0.0.0.0/tcp/4002 \
  -listen /ip4/0.0.0.0/udp/4002/quic-v1 \
  -public-ip <node2-public-ip> \
  -bootstrap /ip4/<seed-ip>/tcp/4001/p2p/<seed-peer-id>
```

**Do not pass policy flags (`-pow-difficulty`, `-repair-interval`, etc.) on joining nodes**;
they are ignored with a warning and replaced by whatever the seed advertises over
`/revika/params`. The only exceptions are the *local* defences (see §5.3), which are
never inherited and are always honored.

---

## 5. Configuration reference

All configuration is via CLI flags; environment variables and a config file are not yet
supported (issue #18). The complete flag list is printed by `./revika-node -h`.

### 5.0 Bootstrap peer file

Instead of repeating `-bootstrap` on every restart, write a text file at
`<data>/bootstrap` (one multiaddr per line; `#` comments and blank lines ignored). The
node reads it on startup when no `-bootstrap` flag is given; an explicit flag always
takes precedence.

```
# /var/lib/revika/bootstrap
/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWExampleSeedPeerID
/ip4/203.0.113.10/udp/4001/quic-v1/p2p/12D3KooWExampleSeedPeerID
```

### 5.1 Core

| Flag | Default | Description |
|------|---------|-------------|
| `-data` | `.revika` | Root directory for node state (shards, identity key, ledger) |
| `-listen` | random TCP+QUIC | libp2p multiaddr to listen on (repeatable) |
| `-public-ip` | — | External IP to advertise for NAT'd nodes |
| `-metrics` | `:9096` | Address for the HTTP status/metrics server; empty to disable |
| `-log-format` | `auto` | `auto` (text on a TTY, JSON otherwise), `text`, or `json` |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-v` | false | Shorthand for `-log-level debug` |

### 5.2 Cluster policy (seed only; joiners inherit)

| Flag | Default | Description |
|------|---------|-------------|
| `-pow-difficulty` | `0` | Argon2id PoW difficulty (leading zero bits) for write admission; `0` = off |
| `-repair` | true | Enable the autonomous repair loop |
| `-repair-interval` | `1h` | How often repair probes and regenerates missing shards |
| `-rebalance` | true | Enable the pairwise load-diffusion rebalance loop |
| `-rebalance-interval` | `1h` | How often rebalance runs |
| `-rebalance-threshold` | `0.10` | Minimum load-fraction gap before offloading a shard |

### 5.3 Local defences (never inherited; apply to every node)

These flags are each node operator's own choice. They are never propagated over
`/revika/params` and are applied even when the joining node provides no other policy flags.

| Flag | Default | Description |
|------|---------|-------------|
| `-quota` | `90 GiB` | Per-owner storage quota in bytes; `0` = unlimited (logged as a warning) |
| `-quota-ramp` | `7d` | Axis B: ramp a new owner from `-quota-initial` to full quota over this age |
| `-quota-initial` | `0.05` | Axis B: initial fraction of quota for a brand-new owner identity |
| `-lease-ttl` | `720h` | Advisory lease lifetime granted on PUT |
| `-gc-interval` | `1h` | How often GC runs |
| `-gc-expired-leases` | false | Also GC shards whose leases have all expired |
| `-write-rate` | 0 | Per-owner write rate cap (writes/s); `0` = disabled |
| `-write-burst` | 0 | Per-owner write burst cap; `0` = defaults to `-write-rate` |
| `-subnet-rate` | `1000` | Axis A: per-subnet request rate cap (req/s) across all verbs; `0` = disabled |
| `-subnet-burst` | `4×rate` | Axis A: per-subnet burst cap |
| `-subnet-prefix4` | `24` | IPv4 prefix length for Axis A subnet buckets |
| `-subnet-prefix6` | `56` | IPv6 prefix length for Axis A subnet buckets |
| `-blocklist` | — | Path to a static blocklist file (peer IDs, CIDRs, IPs; `#` comments) |
| `-blocklist-auto` | `<data>/blocklist.auto` | Auto-blocklist path for the abuse detector; `off` to disable |
| `-rebalance-abuse-tolerance` | 10m | Fast-side slack before a rebalance peer is judged off-schedule |
| `-rebalance-abuse-strikes` | 3 | Possession-lie strikes before local ban |
| `-rebalance-abuse-decay` | 24h | Possession-lie strike decay window |
| `-conn-low` | built-in | Connection-manager low watermark |
| `-conn-high` | built-in | Connection-manager high watermark |
| `-conn-grace` | built-in | Grace period protecting new connections from trimming |
| `-repair-verify` | false | Harden repair survival check: fetch + self-verify (hash==ID) instead of trusting `Has`; costs one shard download per check |
| `-geoip` | `off` | Geolocation source for `/admin` map: `off`, `ip-api`, or path to a MaxMind `.mmdb` |

### 5.4 Storage capacity

`-quota` bounds how much a single owner may store (default 90 GiB). `-capacity` tells
the rebalancer the node's total usable budget for load-balancing decisions (default:
reads the shard filesystem's total size).

---

## 6. Upgrade

1. **Read the changelog / commit log** for breaking protocol changes. Protocol version IDs
   are bumped on frame changes; mismatched nodes fail negotiation (fail-closed). **All
   nodes in a cluster must run matching builds** — there is no backward-compatibility
   path in the development branch.
2. Stop the node gracefully: send `SIGTERM` (or `docker stop`). The node catches it and
   begins shutdown. In-flight streams may be interrupted (graceful drain is not yet
   implemented — issue #17).
3. Replace the binary (or pull the new image).
4. Start the node. It reads the existing ledger and shard store from `-data`.

Ledger schema migrations run automatically at startup (`PRAGMA user_version` — not yet
implemented, issue #16; today any schema change requires a manual backup + fresh `ledger.db`).

---

## 7. Backup and restore

### What to back up

| Path | Contents | Frequency |
|------|----------|-----------|
| `<data>/keys/node.key` | libp2p identity (Peer ID) | Once — regenerating means a new Peer ID |
| `<data>/ledger/ledger.db` | Ownership, leases, quotas, stripe index | Daily (or after every significant write burst) |
| `<data>/shards/` | Encrypted shard blobs | Optional — reconstructible from the network if enough peers hold other shards |

**The identity key is the only irreplaceable file.** Losing it means the node loses its
stable Peer ID and must rejoin the DHT under a new identity; existing provider records
will expire after 48 h. Users' data is not at risk (shards remain on other nodes).

Losing `ledger.db` loses the ownership index: the node can no longer authorize deletions
for its shards, GC will not run correctly, and the quota/lease accounting is gone. A
fresh empty ledger causes no immediate data loss but impairs node operation until it
is repopulated.

### Backup procedure

```bash
# stop the node first, or use SQLite's backup API to get a consistent snapshot
systemctl stop revika-node            # or: docker stop revika-node

cp /var/lib/revika/keys/node.key /backup/revika/node.key
sqlite3 /var/lib/revika/ledger/ledger.db ".backup /backup/revika/ledger.db"

# optional: snapshot the shard store
rsync -a --checksum /var/lib/revika/shards/ /backup/revika/shards/

systemctl start revika-node
```

For an online backup of the SQLite ledger without stopping the node:

```bash
sqlite3 /var/lib/revika/ledger/ledger.db ".backup /backup/revika/ledger-$(date +%Y%m%d).db"
```

SQLite's `.backup` command uses the online-backup API (safe under concurrent writes).

### Restore procedure

```bash
systemctl stop revika-node
cp /backup/revika/node.key /var/lib/revika/keys/node.key
chmod 600 /var/lib/revika/keys/node.key
cp /backup/revika/ledger.db /var/lib/revika/ledger/ledger.db
# restore shards if you have them
rsync -a /backup/revika/shards/ /var/lib/revika/shards/
systemctl start revika-node
```

---

## 8. Monitoring

The HTTP server (`-metrics :9096`, plain HTTP) exposes five endpoints. **Do not expose
this port to the public internet** without a TLS-terminating reverse proxy and access
control — it reveals peer topology.

| Endpoint | Returns |
|----------|---------|
| `GET /healthz` | `200 OK` when the node process is alive; `503` otherwise |
| `GET /readyz` | `200 OK` once the DHT routing table is non-empty (or immediately if DHT is off); `503` otherwise — use this for load-balancer gating |
| `GET /status` | JSON with version, peer ID, listen addrs, disk usage, ledger stats, DHT info, defense config |
| `GET /metrics` | Prometheus text format — scrape with Grafana Alloy/Prometheus |
| `GET /admin` | Browser-facing dashboard (shard map, ledger table, defense panel, optional geo map) |

### Prometheus metrics (key)

| Metric | Type | Description |
|--------|------|-------------|
| `revika_shards_stored_total` | gauge | Number of shards currently in the store |
| `revika_bytes_stored_total` | gauge | Bytes currently stored |
| `revika_repair_runs_total` | counter | Repair loop invocations |
| `revika_repair_shards_regenerated_total` | counter | Shards regenerated by repair |
| `revika_rebalance_moves_total` | counter | Shards moved by the rebalancer |
| `revika_subnet_rate_limit_drops_total` | counter | Streams dropped by the Axis A subnet rate cap |
| `revika_quota_ramp_rejections_total` | counter | Writes rejected by Axis B quota ramp |
| `revika_bootstrap_info` | gauge (label) | Dialable bootstrap address for this node |

### Logging

In production, run with `-log-format json` and ship the structured output to Grafana
Loki (via Alloy) or any JSON-log aggregator. Every event carries a stable `event` key
for filtering:

```bash
./revika-node -log-format json -log-level info 2>&1 | \
  grafana-alloy run alloy-config.river
```

### Recommended alerts

- `/healthz` returns non-200 → node is down.
- `/readyz` returns non-200 for >5 min after startup → DHT bootstrap failed; check
  `-bootstrap` address.
- `revika_repair_shards_regenerated_total` growing continuously → nodes are disappearing
  faster than expected; review availability.
- `revika_subnet_rate_limit_drops_total` growing → flood from a subnet; consider
  tightening `-subnet-rate` or adding a CIDR to the blocklist.

---

## 9. Capacity planning

### Storage

Set `-quota` to 90% or less of the disk partition reserved for revika. The default is
90 GiB; adjust to match your hardware. Monitor `revika_bytes_stored_total` vs the quota.

With erasure coding at `k=4`/`m=2`, each stored byte costs `(k+m)/k = 1.5 bytes` of
raw shard space across the cluster. A cluster of `n` nodes each with `Q` GiB of quota
can hold approximately `n × Q / 1.5` GiB of user data, assuming even distribution.

The rebalancer spreads load automatically. Monitor `revika_rebalance_moves_total` to
confirm it is running. A node that fills up will reject new writes with a `quota`
rejection reason visible in the logs and on `/admin`.

### Network

Each shard is at most 64 MiB (configurable). A `PUT` with `k=4`/`m=2` sends
`k+m = 6` shards to 6 different nodes. Repair and rebalance add background traffic.
Enable QUIC (UDP) listeners for better performance on high-latency paths.

QUIC uses a large UDP receive buffer. Set the kernel limit once per host:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
# persist:
echo 'net.core.rmem_max=7500000' | sudo tee /etc/sysctl.d/99-revika.conf
echo 'net.core.wmem_max=7500000' | sudo tee -a /etc/sysctl.d/99-revika.conf
sudo sysctl -p /etc/sysctl.d/99-revika.conf
```

### Connection limits

The libp2p connection manager defaults keep connections bounded. For a well-connected
node in a large cluster, tune `-conn-high` upward (e.g. `-conn-high 400`). Watch
`revika_libp2p_connections` in `/metrics`.

---

## 10. Troubleshooting

### Node does not appear in the DHT

Check `/readyz`: if it returns `not ready: DHT routing table empty`, the node has not
connected to any bootstrap peer.

- Verify `-bootstrap` is set and points to a running node's full multiaddr
  (`/ip4/…/tcp/…/p2p/12D3KooW…`).
- Verify the bootstrap node's TCP and UDP ports are reachable (firewall).
- Check logs for `dial failed` events.

### Writes rejected with `quota` reason

The owner has reached their per-node quota. Options:

- Increase `-quota` on the node (or set `-quota 0` for unlimited, with a warning).
- Free shards: the owner can `rm` data from their namespace.
- Add more nodes to the cluster so the rebalancer distributes load.

### Writes rejected with `pow` reason

The client's signing key does not meet this node's PoW difficulty requirement. The
client must re-generate their signing key with `revika-ctl keygen` (or `revika-ctl
connect` against a bootstrap that advertises the policy). Check the seed's
`-pow-difficulty` flag.

### A peer is auto-blocked

`blocklist.auto` (default `<data>/blocklist.auto`) records peers the abuse detector has
banned. Inspect it:

```bash
cat /var/lib/revika/blocklist.auto
```

To unblock a peer, remove its entry from the file and restart the node. The static
`-blocklist` file is never mutated by the detector.

### Shard corruption detected

The store re-hashes every shard on read and returns `ErrCorrupt` on mismatch. The repair
loop detects the missing (corrupt) shard and regenerates it from parity — no action
needed. If corruption is widespread:

- Check the disk for hardware errors (`smartctl -a /dev/sdX`).
- Monitor `revika_repair_shards_regenerated_total` — sustained growth signals a failing
  disk.

### Logs show "shard already exists" on repair PUT

This is harmless: a competing repair cycle on another node put the shard first.
Content-addressing makes the result identical; the node with the duplicate simply returns
the existing entry.

---

## See also

- [Architecture.md](../Architecture.md) — design rationale and capability chain
- [docs/Production.md](Production.md) — production readiness gap tracker
- [security/Defence.md](../security/Defence.md) — defence mechanism catalogue
- [security/Security.md](../security/Security.md) — threat scenario catalogue
