# N-ORG-SYB-02 — Collusion between nodes

- **Target**: Nodes
- **Category**: Organisational threats › Sybil / collusion
- **Identifier**: N-ORG-SYB-02

## Description
Several nodes coordinate their actions to deceive the placement, audit or redundancy mechanisms.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Trusted Relationship | T1199 | Colluding nodes coordinate their responses to appear independent to placement and audit. | Distribution of shards by erasure coding over distinct owners (Ed25519 pubkey): no colluding subset smaller than `k` compromises the reconstruction. |
| Establish Accounts | T1585 | The colluders maintain several coordinated identities to simulate a diversity of redundancy. | Independent possession probes recomputing the content hash: the colluders cannot satisfy the audit without actually holding distinct shards. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon k=4/m=2 coding + repair | T1199 | — | SC-36 |
| Placement spread over independent owners | T1199 | — | SC-36 |
| Probes + possession challenges | T1585 | — | SI-7 |
| CTID controls (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| D3FEND techniques (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
