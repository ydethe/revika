# C-CONF-01 — Inferring the existence of data

- **Target**: Clients
- **Category**: Confidentiality
- **Identifier**: C-CONF-01

## Description
An observer infers that a file or dataset exists from indirect signals, without having access to it.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Network Service Discovery | T1046 | The observer queries the `/revika` DHT and the nodes to spot provider records that reveal the existence of shards. | Confine discovery to the private `/revika` DHT prefix and limit public provider announcements, the shards remaining opaque ciphertext addressed by hash. |
| Network Sniffing | T1040 | Analysing libp2p flows (volumes, access patterns) hints that a dataset is present. | Encrypted/authenticated libp2p transport and per-peer rate-limiting (`internal/net/defense.go`) reducing traffic analysis. |
| Gather Victim Host Information | T1592 | The attacker cross-references host clues (disk occupancy, shard count) to conclude that data exists. | Per-owner quotas and TTL leases in the SQLite ledger normalizing the storage footprint, without exposing the content. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + peer diversity | T1046 | — | SC-36 |
| Content-hash addressing | T1046 | D3-FH | SI-7 |
| Encrypted / authenticated libp2p transport | T1040 | D3-MENCR | SC-8 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1040 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1592 | — | SC-6 |
| CTID controls (neo4j) | T1046 | — | AC-4, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-7, SC-46, SI-3, SI-4 |
| CTID controls (neo4j) | T1040 | — | AC-16, AC-17, AC-18, AC-19, CM-7, IA-2, IA-5, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1046 | D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
| D3FEND techniques (neo4j) | T1040 | D3-OSM | — |
