# C-INT-DAT-04 — Logical deletion

- **Target**: Clients
- **Category**: Integrity › Data
- **Identifier**: C-INT-DAT-04

## Description
Data is marked deleted or made inaccessible on the client side without a legitimate deletion.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Destruction | T1485 | A node destroys or marks shards as deleted without a legitimate order from the owner. | Reed-Solomon redundancy (`m` parities) spread across independent nodes and mandatory repair regenerating the missing shards. |
| Indicator Removal: File Deletion | T1070.004 | Shards are erased from local storage to make the data inaccessible. | TTL-based leases and deletion conditioned on a signed owner token, with an append-only chained audit log detecting illegitimate removals. |
| Inhibit System Recovery | T1490 | Putting shards out of reach aims to prevent recovery of the file. | Availability probes (`internal/repair`) triggering deterministic regeneration of shards from the survivors. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1485 | — | SC-36 |
| Placement spread over independent owners | T1485 | — | SC-36 |
| Short-TTL capabilities + revocation | T1070.004 | — | AC-3 |
| Append-only chained logs + signed seq | T1070.004 | — | AU-9 |
| Probes + proof-of-possession challenges | T1490 | — | SI-7 |
| CTID controls (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
