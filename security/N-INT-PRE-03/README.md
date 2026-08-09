# N-INT-PRE-03 — Proof pooling

- **Target**: Nodes
- **Category**: Integrity › Proofs
- **Identifier**: N-INT-PRE-03

## Description
Several nodes share a single copy of the data but each present a proof, feigning a redundancy that does not exist.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | Distinct nodes present themselves as independent custodians while they share a single copy. | Placement by distinct erasure-coded shards (Reed-Solomon k=4/m=2): each node must hold a different shard, verified by hash, not substitutable. |
| Impersonation | T1656 | Analogue: the fake redundancy usurps the role of several independent custodians. | Simultaneous, time-constrained proof-of-possession challenges on distinct shards, which a single shared store cannot satisfy in parallel. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1036 | — | SC-36 |
| Placement spread across independent owners | T1036 | — | SC-36 |
| Probes + proof-of-possession challenges | T1656 | — | SI-7 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
