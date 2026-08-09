# C-DISP-04 — Mass reconstruction requests

- **Target**: Clients
- **Category**: Availability
- **Identifier**: C-DISP-04

## Description
A client triggers mass erasure-coded reconstructions to saturate computation and bandwidth.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Mass Reed-Solomon reconstruction requests saturate the nodes' CPU and bandwidth. | Condition repair on a signed repair grant (`stripe`) and rate-limit reconstructions per-owner. |
| Resource Hijacking | T1496 | The attacker hijacks the nodes' computation and bandwidth through needless reconstructions. | Bound via the ledger quotas and TTL leases, reserving reconstructions for the legitimate repair process. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signed repair grant | T1499.003 | D3-MAN | AC-3 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.003 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1496 | — | SC-6 |
| CTID controls (neo4j) | T1499.003 | — | AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
