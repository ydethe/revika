# N-AC-03 — Serving data after expiry

- **Target**: Nodes
- **Category**: Access control
- **Identifier**: N-AC-03

## Description
A node keeps providing data beyond the expiry of the corresponding lease or token.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | A signed access token that has expired is replayed to unduly extend access to the shards. | Strict verification of the token's TTL and signed timestamp on every request, rejecting any expired token. |
| Valid Accounts | T1078 | An expired lease keeps justifying access that should have ceased. | Lease expiry managed by the SQLite ledger with GC purge, refusing service as soon as the TTL is exceeded. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-replay nonce/clock/seq + TTL | T1550.001 | — | SC-23 |
| Per-owner SQLite ledger + quotas/leases | T1078 | — | SC-6 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
