# C-INT-JRN-04 — Re-emission of events

- **Target**: Clients
- **Category**: Integrity › Journal
- **Identifier**: C-INT-JRN-04

## Description
Already-recorded log events are re-emitted to distort the count or the history.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | A replay analogue: already-recorded events are re-emitted to distort the count and history. | Assigning each event a signed nonce/sequence number, any duplicate being detected and rejected. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | The re-emission reuses authentic signed messages outside their original occurrence. | Chaining entries by hash and timestamping/signing each occurrence, preventing the insertion of an event already present in the chain. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-replay nonce/clock/seq + TTL | T1565.002 | — | SC-23 |
| Append-only chained logs + signed seq | T1550.001 | — | AU-9 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
