# N-DISP-07 — Saturation of CPU, memory, disk or bandwidth

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-07

## Description
A node is targeted (or over-commits) until its resources are exhausted, rendering it unable to serve.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service | T1499 | The node is saturated (CPU/memory/disk) until it can no longer serve its shards. | The `ResourceManager` + `ConnManager` of `internal/net/defense.go` bounding connections and resources, with a `ConnectionGater` (per-peer/subnet blocklist). |
| OS Exhaustion Flood | T1499.001 | The influx of connections/requests exhausts the node's system resources. | Per-peer / per-owner rate-limiting (keyed on the Ed25519 pubkey) and write admission conditioned on a proof of work (argon2id). |
| Network Denial of Service | T1498 | Bandwidth saturation prevents the node from sending/receiving the shards. | Per-owner quotas from the SQLite ledger and Reed-Solomon redundancy allowing service from other nodes during the saturation. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1499 | D3-NTF | SC-7 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.001 | D3-ITF | SC-5 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1499.001 | — | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1498 | — | SC-6 |
| Reed-Solomon coding k=4/m=2 + repair | T1498 | — | SC-36 |
| CTID controls (neo4j) | T1499 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1499.001 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| D3FEND techniques (neo4j) | T1499 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1499.001 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
