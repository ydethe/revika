# C-COL-04 — Coordinated creation of false events

- **Target**: Clients
- **Category**: Collusion
- **Identifier**: C-COL-04

## Description
Clients fabricate false events in concert to deceive the log or the registry.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Clients insert false events in concert into the log or the registry. | Signed, chained (hash-chain) append-only audit log: any insertion or rewrite breaks the chain and is detected. |
| Impersonation | T1656 | The false events mimic legitimate actions of other actors to deceive the registry. | Ed25519-signed events and content-hash addressing, imposing a verifiable provenance for every entry. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1565.001 | — | AU-9 |
| Ed25519 signatures / capabilities | T1656 | D3-MAN | AU-10 |
| Content-hash addressing | T1656 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
