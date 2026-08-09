# C-DISP-03 — Interrupted downloads

- **Target**: Clients
- **Category**: Availability
- **Identifier**: C-DISP-03

## Description
A client systematically initiates then interrupts downloads to waste the nodes' resources.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | Abusing the initiate/interrupt cycle exploits the transfer protocol to waste resources. | Bound per-request time and resources via `ResourceManager` and close abusive unfinished transfers. |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Repeating aborted downloads saturates the nodes' service capacity. | Rate-limit per-owner (keyed on the Ed25519 pubkey) and penalize via the ledger peers with repeatedly interrupted transfers. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1499.004 | D3-NTF | SC-7 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.003 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1499.003 | — | SC-6 |
| CTID controls (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
