# C-INT-DAT-01 — Sending corrupted data

- **Target**: Clients
- **Category**: Integrity › Data
- **Identifier**: C-INT-DAT-01

## Description
An actor gets the client to accept corrupted data that does not reconstruct correctly.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | A shard is corrupted in transit so that the client receives data that does not reconstruct. | Systematic verification by recomputing the content hash on receipt, rejecting any altered shard. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | A node serves a corrupted stored shard instead of the legitimate ciphertext. | AES-256-GCM AEAD (authentication failure on read) combined with content-hash addressing detecting corruption. |
| Inhibit System Recovery | T1490 | Corrupting several shards aims to prevent reconstruction of the file. | Reed-Solomon erasure coding (`k=4`, `m=2`, any `k` reconstructs) and mandatory repair over deterministic ciphertext. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash recompute on receipt | T1565.002 | D3-FH | SI-7 |
| Client-side AES-256-GCM encryption | T1565.001 | D3-MENCR | SC-28 |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1490 | — | SC-36 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
