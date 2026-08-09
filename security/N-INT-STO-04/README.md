# N-INT-STO-04 — Local data reorganisation

- **Target**: Nodes
- **Category**: Integrity › Storage
- **Identifier**: N-INT-STO-04

## Description
The node locally reorders or remaps its shards so as to break the expected association between identifier and content.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The node locally remaps the ID→content index so that an identifier points to a shard that is not its own. | Content-hash addressing: the ID is derived from the content, so any remapping produces a shard whose hash does not match and which is rejected. |
| Masquerading | T1036 | P2P analogue: a shard is presented under another's identifier, passing itself off as content it is not. | Systematic recomputation of the hash on read + erasure coding/repair falling back to the valid erasure replicas. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Recompute the hash on receipt | T1036 | D3-FH | SI-7 |
| Reed-Solomon k=4/m=2 coding + repair | T1036 | — | SC-36 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
