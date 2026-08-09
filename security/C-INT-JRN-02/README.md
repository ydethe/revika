# C-INT-JRN-02 — Contradictory events

- **Target**: Clients
- **Category**: Integrity › Journal
- **Identifier**: C-INT-JRN-02

## Description
Contradictory log entries are produced to render the history unusable.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Contradictory entries corrupt the stored history to render it unusable. | Chaining entries by hash and signing them, any order or content inconsistent with the chain being rejected on verification. |
| Indicator Removal | T1070 | The contradiction serves to drown out and neutralize the authentic indicators of an action. | Attaching each entry to an Ed25519 identity and a signed sequence number, allowing the non-authenticated entries to be isolated. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Append-only chained logs + signed seq | T1565.001 | — | AU-9 |
| Ed25519 signatures / capabilities | T1070 | D3-MAN | AU-10 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| CTID controls (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
