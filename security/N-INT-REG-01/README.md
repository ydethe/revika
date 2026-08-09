# N-INT-REG-01 — Double publication

- **Target**: Nodes
- **Category**: Integrity › Registry
- **Identifier**: N-INT-REG-01

## Description
A node publishes two divergent versions of the same record in the distributed registry to create an exploitable inconsistency.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | The node writes two contradictory values for the same entry in order to alter the consistent state of the registry. | Each entry is Ed25519-signed and hash-chained (append-only), making any equivocation detectable by comparing the chains across nodes. |
| Rogue Domain Controller | T1207 | P2P analogue: the node behaves as an illegitimate peer broadcasting divergent "authoritative" records. | Content-hash addressing + cross-reconciliation of the SQLite ledger between peers, which rejects non-monotonic conflicting publications. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1565.001 | — | AU-9 |
| Content-hash addressing | T1207 | D3-FH | SI-7 |
| Cross-peer ledger corroboration | T1207 | — | AU-6 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
