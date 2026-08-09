# N-INT-REG-04 — Creation of fictitious events

- **Target**: Nodes
- **Category**: Integrity › Registry
- **Identifier**: N-INT-REG-04

## Description
A node records in the registry events that never took place (fake storage, fake transfer).

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | The node fabricates registry entries (fake storage, fake transfer) with no underlying reality. | Every event must reference a shard verifiable by content hash and a signed capability/grant, otherwise it is rejected. |
| Masquerading | T1036 | The fake events pass off non-existent activity as a legitimate storage or transfer operation. | Cross-corroboration: a storage event is admitted only after proof of possession verifiable by the checking peer. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Ed25519 signatures / capabilities | T1565.001 | D3-MAN | AU-10 |
| Inter-peer cross-corroboration of the ledger | T1036 | — | AU-6 |
| Probes + possession challenges | T1036 | — | SI-7 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
