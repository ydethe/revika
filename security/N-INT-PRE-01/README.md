# N-INT-PRE-01 — Fake storage proofs

- **Target**: Nodes
- **Category**: Integrity › Proofs
- **Identifier**: N-INT-PRE-01

## Description
A node produces a storage proof without actually holding the corresponding data.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | The node presents itself as a compliant holder of a shard while it does not store it. | Proof of possession via challenge-response recomputing the shard's content hash, impossible to satisfy without holding the exact bytes. |
| Impersonation | T1656 | Analogue: the node feigns the serving capability of a legitimate custodian to capture reputation/quota. | Mandatory repair on deterministic ciphertext and periodic probes: a custodian unable to serve is detected and its shards regenerated elsewhere. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + proof-of-possession challenges | T1036 | — | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1656 | — | SC-36 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
