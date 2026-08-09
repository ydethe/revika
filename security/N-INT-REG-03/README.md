# N-INT-REG-03 — Omission of events

- **Target**: Nodes
- **Category**: Integrity › Registry
- **Identifier**: N-INT-REG-03

## Description
A node fails to write certain events it should publish, leaving the registry incomplete.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The node suppresses upstream the publication of certain events it should record. | Append-only signed and chained log: the omission creates detectable gaps via signed sequence numbers and cross-peer corroboration. |
| Indicator Removal | T1070 | The lack of a record leaves the registry incomplete and masks the node's real activity. | Completeness attestations corroborated by peers (ledger ownership/stripe index) that flag expected but absent events. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1562.001 | — | AU-9 |
| Cross-peer ledger corroboration | T1070 | — | AU-6 |
| CTID controls (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
