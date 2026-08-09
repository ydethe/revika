# N-INT-MET-01 — Metadata falsification

- **Target**: Nodes
- **Category**: Integrity › Metadata
- **Identifier**: N-INT-MET-01

## Description
The node modifies the metadata associated with shards (owner, lease, quota, stripe) to deceive the other participants.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The node falsifies in its SQLite ledger the ownership, lease, quota or stripe metadata attached to shards. | Signed erasure metadata (`stripe.Descriptor`, signed repair grant): falsified metadata invalidates the Ed25519 signature and is rejected. |
| Masquerading | T1036 | By rewriting a shard's owner, the node makes a piece of data appear to belong to an owner other than the real holder. | Ownership bound to the owner's self-certifying Ed25519 pubkey and signed capabilities wrapped with ML-KEM-768: ownership is not reassignable locally by the node. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signed erasure metadata (stripe.Descriptor) | T1565.001 | D3-MAN | SI-7 |
| Signed repair grant | T1565.001 | D3-MAN | AC-3 |
| Ed25519 signatures / capabilities | T1036 | D3-MAN | AU-10 |
| ML-KEM-768 wrapping (cap wrapping) | T1036 | D3-MENCR | SC-12 |
| CTID controls (neo4j) | T1565.001 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
