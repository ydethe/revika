# N-INT-STO-01 — Shard tampering

- **Target**: Nodes
- **Category**: Integrity › Storage
- **Identifier**: N-INT-STO-01

## Description
A node modifies the content of a shard it hosts, corrupting the data it is supposed to return identically (content-hash addressed).

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The node tampers at rest with the content of a shard it stores, breaking its correspondence with the content hash that addresses it. | Content-hash addressing: any tampering is detected on read by recomputing the hash, disqualifying the corrupted shard. |
| Data Destruction | T1485 | By irreparably corrupting the shard, the node effectively destroys the portion of data it was meant to keep. | Reed-Solomon erasure coding (`k=4`, `m=2`) + mandatory repair on deterministic ciphertext regenerating the lost shard from the others. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Reed-Solomon k=4/m=2 coding + repair | T1485 | — | SC-36 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
