# N-PROTO-04 — Modified software

- **Target**: Nodes
- **Category**: Protocol threats
- **Identifier**: N-PROTO-04

## Description
An operator runs an altered version of the node software that deviates from the expected protocol.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Compromise Host Software Binary | T1554 | The operator runs a modified node binary that departs from the expected revika protocol. | "Dumb, untrusted" node model: confidentiality rests on client-side encryption and hash addressing, a rogue node seeing only opaque ciphertext. |
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | An altered version of the software is distributed then deployed by operators. | Build reproducibility and integrity verification of artefacts, with a pinned Go toolchain (`go 1.26`) and pinned dependencies. |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The modified software disables the compliance checks the node should apply. | Design that does not make security depend on the good behaviour of a node: Reed-Solomon erasure coding + mandatory repair tolerate a deviant node. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| "Dumb/untrusted" node + User-side re-verification | T1554 | — | SA-8 |
| Reproducible build / pinned supply chain | T1195.002 | — | SR-4 |
| Reed-Solomon k=4/m=2 coding + repair | T1562.001 | — | SC-36 |
| CTID controls (neo4j) | T1554 | — | CM-2, CM-5, CM-6, IA-9, SI-3, SI-7, SR-4, SR-5, SR-11 |
| CTID controls (neo4j) | T1195.002 | — | CA-2, CA-7, CM-7, CM-11, RA-5, RA-10, SA-22, SI-2, SR-5, SR-11 |
| D3FEND techniques (neo4j) | T1554 | D3-EAL, D3-EDL, D3-FA, D3-LAM, D3-NTA, D3-PA, D3-PM | — |
| D3FEND techniques (neo4j) | T1195.002 | D3-NTA | — |
