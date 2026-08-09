# N-CONF-03 — Metadata correlation

- **Target**: Nodes
- **Category**: Confidentiality › Data
- **Identifier**: N-CONF-03

## Description
Cross-referencing the metadata visible on the node side (content identifiers, owners, sizes, timestamps) makes it possible to reconstitute links between shards, and hence between files or users.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data from Information Repositories | T1213 | The node queries its SQLite ledger (CID, owners, sizes, timestamps) to correlate the shards with each other. | Content-hash addressing making the CIDs opaque and a ledger limited to the strict minimum (ownership/lease/quota), with no link to the logical file. |
| Automated Collection | T1119 | Automated collection and cross-referencing of the metadata of several shards to infer relations. | Per-owner rate-limiting keyed on the Ed25519 pubkey (`internal/net/defense.go`) capping the volume of metadata observable by a peer. |
| Gather Victim Org Information | T1591 | Reconstitution of file ↔ user links from the aggregated metadata. | Erasure coding + distributed placement across independent nodes: no node sees the whole set of shards of a given file. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1213 | D3-FH | SI-7 |
| Per-owner SQLite ledger + quotas/leases | T1213 | — | SC-6 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1119 | D3-ITF | SC-5 |
| Reed-Solomon coding k=4/m=2 + repair | T1591 | — | SC-36 |
| Distributed placement across independent owners | T1591 | — | SC-36 |
| CTID controls (neo4j) | T1213 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-21, AC-23, CA-7, CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, IA-2, IA-4, IA-8, RA-5, SC-28, SC-37, SI-4 |
| CTID controls (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-4, SC-36, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1213 | D3-EAL, D3-EDL, D3-ITF, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-RAPA, D3-UAP, D3-UDTA | — |
| D3FEND techniques (neo4j) | T1119 | D3-OSM | — |
