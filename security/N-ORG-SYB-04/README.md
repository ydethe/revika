# N-ORG-SYB-04 — Control of a regional majority

- **Target**: Nodes
- **Category**: Organisational threats › Sybil / collusion
- **Identifier**: N-ORG-SYB-04

## Description
An actor controls enough nodes in a region to dominate the decisions or the local storage.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Establish Accounts | T1585 | The actor amasses enough node identities in a region to dominate placement and storage there. | Proof of work on the identity (argon2id) + per-owner quotas: concentrating a regional weight costs CPU and stays capped by the ledger. |
| Botnet | T1583.005 | The concentrated regional fleet operates as a botnet dominating local decisions. | Placement policy imposing inter-owner and inter-region diversity, controlled by observed subnet/AS via the `ConnectionGater`. |
| Trusted Relationship | T1199 | The coordinated regional nodes form a trusted relationship abused to capture local storage. | Erasure coding dispersing the shards outside a single region: no complete `k` can reside in the dominated area. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1585 | — | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1585 | — | SC-6 |
| Network-measured placement diversity | T1583.005 | — | SC-36 |
| Reed-Solomon k=4/m=2 coding + repair | T1199 | — | SC-36 |
| CTID controls (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| D3FEND techniques (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
