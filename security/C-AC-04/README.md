# C-AC-04 — Privilege escalation

- **Target**: Clients
- **Category**: Access control
- **Identifier**: C-AC-04

## Description
A client turns limited access into access broader than what was granted to it.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Abuse Elevation Control Mechanism | T1548 | The client subverts the capability-granting mechanism to extend its scope beyond what was granted. | Capabilities cryptographically bound to a precise scope (read-capability = manifest location + ML-KEM encapsulated key), not extensible without a new signed capability. |
| Exploitation for Privilege Escalation | T1068 | The client exploits an access-control flaw to obtain higher rights. | Access control carried by cryptography rather than by server roles, and ownership/quota arbitrated by the per-owner SQLite ledger. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ML-KEM-768 encapsulation (cap wrapping) | T1548 | D3-MENCR | SC-12 |
| Ed25519 signatures / capabilities | T1548 | D3-MAN | AU-10 |
| Per-owner SQLite ledger + quotas/leases | T1068 | — | SC-6 |
| CTID controls (neo4j) | T1548 | — | AC-2, AC-3, AC-5, AC-6, AC-16, CA-7, CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, IA-2, RA-5, SC-18, SC-34, SI-2, SI-3, SI-4, SI-7, SI-12, SI-16 |
| CTID controls (neo4j) | T1068 | — | AC-2, AC-4, AC-6, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, RA-10, SC-2, SC-3, SC-7, SC-18, SC-30, SC-39, SI-2, SI-3, SI-4, SI-5, SI-7 |
| D3FEND techniques (neo4j) | T1548 | D3-EAL, D3-EDL, D3-FA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1068 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
