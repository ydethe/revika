# C-INT-DAT-03 — Incompatible versions

- **Target**: Clients
- **Category**: Integrity › Data
- **Identifier**: C-INT-DAT-03

## Description
The client is presented with a mix of incompatible versions of the same content, preventing a consistent reconstruction.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Nodes serve shards from different versions of the same content, mixing inconsistent stripes. | Content-hash addressing binding each shard to its exact version, the signed manifest fixing the consistent set to retrieve. |
| Inhibit System Recovery | T1490 | Mixing versions prevents gathering `k` compatible shards and blocks reconstruction. | Reed-Solomon coding with selection of the `k` shards of the expected hash and deterministic repair over ciphertext. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Versioned Ed25519-signed manifest | T1565.001 | D3-MAN | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1490 | — | SC-36 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
