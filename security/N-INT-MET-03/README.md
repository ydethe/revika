# N-INT-MET-03 — History rewriting

- **Target**: Nodes
- **Category**: Integrity › Metadata
- **Identifier**: N-INT-MET-03

## Description
The node reconstructs its local metadata history after the fact to hide an action or simulate another.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Indicator Removal | T1070 | The node rewrites its metadata history after the fact to erase the traces of an action or fabricate another. | Append-only, signed and hash-chained audit logs: any rewrite breaks the chaining and becomes detectable. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The reconstruction of the history manipulates the stored metadata records to simulate a different past state. | Events timestamped by signed nonces/sequence numbers: a re-forged history cannot reproduce the original consistent signatures. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1070 | — | AU-9 |
| Anti-replay nonce/clock/seq + TTL | T1565.001 | — | SC-23 |
| CTID controls (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
