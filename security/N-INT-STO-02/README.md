# N-INT-STO-02 — Serving a corrupted shard

- **Target**: Nodes
- **Category**: Integrity › Storage
- **Identifier**: N-INT-STO-02

## Description
On read, the node returns a shard whose content does not match the requested identifier, sabotaging the erasure-coded reconstruction.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | The node serves in transit, on read, falsified content that does not match the requested shard identifier. | Verification by recomputing the content hash on receipt: a shard that does not re-hash to the requested ID is rejected. |
| Inhibit System Recovery | T1490 | By serving corrupted shards, the node seeks to prevent the erasure-coded reconstruction of the file. | Reed-Solomon coding (any `k` of `k+m` reconstructs) + mandatory repair: the read falls back to other valid shards and regenerates the missing ones. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Recompute the hash on receipt | T1565.002 | D3-FH | SI-7 |
| Reed-Solomon k=4/m=2 coding + repair | T1490 | — | SC-36 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
