# C-DISP-01 — Flood

- **Target**: Clients
- **Category**: Availability
- **Identifier**: C-DISP-01

## Description
A malicious client floods the network with requests to degrade availability for others.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | The deluge of application requests exhausts the nodes and degrades the service for others. | Apply per-peer / per-owner rate-limiting (keyed on the Ed25519 pubkey) and the ledger quotas to cap the request rate. |
| Network Denial of Service: Direct Network Flood | T1498.001 | Directly flooding the network saturates the nodes' bandwidth and processing capacity. | Wire the defences of `internal/net/defense.go` (`ResourceManager` + `ConnManager`) and block abusive peers/subnets via `ConnectionGater`. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.003 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1499.003 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1498.001 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1498.001 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-15 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1498.001 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
