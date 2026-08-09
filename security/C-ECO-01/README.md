# C-ECO-01 — Mass data creation

- **Target**: Clients
- **Category**: Economic threats
- **Identifier**: C-ECO-01

## Description
A client creates a massive volume of data to exhaust the network's resources or quota.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | The client floods the nodes with creations to exhaust their available storage. | Per-owner quotas and TTL leases held by the SQLite ledger, capping the storage consumable per identity. |
| Resource Hijacking | T1496 | The client monopolizes the network's storage resources to the detriment of others. | Per-owner rate-limiting keyed on the Ed25519 pubkey and write admission conditioned on a proof of work (argon2id). |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner SQLite ledger + quotas/leases | T1499.003 | — | SC-6 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1496 | D3-ITF | SC-5 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1496 | — | SC-5 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
