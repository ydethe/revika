# N-AC-01 — Ignoring a revocation

- **Target**: Nodes
- **Category**: Access control
- **Identifier**: N-AC-01

## Description
A node keeps serving data to a requester whose access has been revoked.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | The requester exploits a capability that was once legitimate but is now revoked to keep accessing the shards. | Revocation propagated and verified on every request, with short-TTL signed capabilities forcing renewal rather than a permanent right. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | A signed access token, valid when issued, is reused after revocation to justify access. | Check of the revocation state in the node's SQLite ledger before serving, invalidating any listed token even if it has not yet expired. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Short-TTL capabilities + revocation | T1078 | — | AC-3 |
| Per-owner SQLite ledger + quotas/leases | T1550.001 | — | SC-6 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
