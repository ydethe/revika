# N-DISP-01 — Deletion of a shard

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-01

## Description
A node erases a shard it had committed to keep, reducing the redundancy available for reconstruction.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Destruction | T1485 | The node destroys an entrusted encrypted shard, curtailing the stripe's redundancy. | Reed-Solomon erasure coding (`k=4`, `m=2`) + mandatory repair on deterministic ciphertext, regenerating any lost shard at its hash address. |
| File Deletion | T1070.004 | Deleting the shard file on the node's disk erases the proof of retention. | TTL leases and an ownership/stripe index in the SQLite ledger, cross-checked against availability probes that detect the shard's absence. |
| Inhibit System Recovery | T1490 | By lowering the number of shards below `k`, the node aims to prevent reconstruction of the file. | Redundant placement across independent nodes and automatic triggering of repair as soon as a probe signals degraded redundancy. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1485 | — | SC-36 |
| Per-owner SQLite ledger + quotas/leases | T1070.004 | — | SC-6 |
| Probes + possession challenges | T1070.004 | — | SI-7 |
| Distributed placement across independent owners | T1490 | — | SC-36 |
| CTID controls (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
