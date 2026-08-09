# N-ECO-01 — Declaring fictitious capacity

- **Target**: Nodes
- **Category**: Economic threats
- **Identifier**: N-ECO-01

## Description
A node advertises a storage capacity greater than its real capacity to attract placements.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | The node presents a falsified capacity attribute to appear better provisioned than it is and capture placements. | Do not trust advertisements: validate actual holding through availability probes (`internal/repair`) that recompute the content hash of shards, and cap via the per-owner quota of the SQLite ledger. |
| Impersonation | T1656 | P2P analogue: the node passes itself off as an honest, well-provisioned peer in order to gain the trust of the placement policy. | Placement keyed on the self-certified Ed25519 pubkey and periodic verification via proof-of-possession challenge (hash addressing) rather than on the peer's declarations. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + proof-of-possession challenges | T1036, T1656 | — | SI-7 |
| Per-owner SQLite ledger + quotas/leases | T1036 | — | SC-6 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1656 | — | SC-5 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
