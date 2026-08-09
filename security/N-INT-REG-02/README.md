# N-INT-REG-02 — Registry rewriting

- **Target**: Nodes
- **Category**: Integrity › Registry
- **Identifier**: N-INT-REG-02

## Description
A node attempts to modify, after the fact, entries already written in the distributed registry.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | The node rewrites already-validated registry entries to change their historical content. | Append-only signed and hash-chained log: any rewrite breaks the hash-chain and invalidates the downstream Ed25519 signatures. |
| Indicator Removal | T1070 | The after-the-fact modification aims to erase or disguise the trace of past events. | Signed ledger replication between peers and verification of the chain's continuity, preventing acceptance of an altered version. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1565.001 | — | AU-9 |
| Cross-peer ledger corroboration | T1070 | — | AU-6 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| CTID controls (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
