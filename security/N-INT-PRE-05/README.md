# N-INT-PRE-05 — Falsification of availability proofs

- **Target**: Nodes
- **Category**: Integrity › Proofs
- **Identifier**: N-INT-PRE-05

## Description
A node provides a deceitful proof that it is available and reachable to serve data that it cannot in fact provide.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | The node declares itself reachable and able to serve data that it cannot effectively provide. | Availability probes requiring the actual return of the hash-verified shard, and not a mere declarative attestation. |
| Impersonation | T1656 | Analogue: the node usurps the status of a functional custodian in the placement/repair computation. | Mandatory repair triggered as soon as a probe fails, regenerating the shards from the k survivors on other nodes. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + proof-of-possession challenges | T1036 | — | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1656 | — | SC-36 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
