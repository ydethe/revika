# C-INT-JRN-03 — Massive noise

- **Target**: Clients
- **Category**: Integrity › Journal
- **Identifier**: C-INT-JRN-03

## Description
The log is drowned under a massive volume of irrelevant events to mask an action.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The massive event noise masks the indicators of the real action. | Rate-limiting event generation per-owner (keyed on the Ed25519 pubkey) to throttle the floods intended to drown the log. |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | The event volume saturates the logging/analysis capacity. | Applying per-owner quotas and `ResourceManager`/`ConnManager` limits to cap the rate of emitted entries. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner rate-limiting (Ed25519 pubkey) | T1562.001 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1499.003 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1499.003 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
