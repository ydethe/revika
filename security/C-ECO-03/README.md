# C-ECO-03 — Repeated creation/deletion

- **Target**: Clients
- **Category**: Economic threats
- **Identifier**: C-ECO-03

## Description
A client alternates creations and deletions to exploit the asymmetric costs of operations.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | The rapid creation/deletion cycle exploits the cost asymmetry to exhaust the nodes. | Per-owner rate-limiting and ledger TTL quotas/leases absorbing the churn, with deferred garbage collection. |
| Data Destruction | T1485 | Repeated deletions aim to impose a disproportionate repair/cleanup cost. | Reed-Solomon erasure coding + deterministic repair on ciphertext, and a signed append-only audit log tracing every deletion. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.003 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1499.003 | — | SC-6 |
| Reed-Solomon coding k=4/m=2 + repair | T1485 | — | SC-36 |
| Chained append-only logs + signed seq | T1485 | — | AU-9 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
