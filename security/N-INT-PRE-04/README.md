# N-INT-PRE-04 — Fabricating proofs without data

- **Target**: Nodes
- **Category**: Integrity › Proofs
- **Identifier**: N-INT-PRE-04

## Description
A node computes or guesses a valid proof without ever having stored the underlying data.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Weaken Encryption | T1600 | The node exploits a weak proof scheme to compute/guess a valid proof without holding the data. | Proof based on the content hash of the whole shard with an unpredictable challenge, whose space makes computation without the real bytes infeasible. |
| Masquerading | T1036 | The fabricated proof makes the node appear as an effective custodian of the data. | Challenge-response over random positions of the hash-addressed shard, requiring full possession of the exact bytes. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + proof-of-possession challenges | T1036 | — | SI-7 |
| Content-hash addressing | T1600 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
