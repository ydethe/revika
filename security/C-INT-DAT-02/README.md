# C-INT-DAT-02 — Unauthorized modification

- **Target**: Clients
- **Category**: Integrity › Data
- **Identifier**: C-INT-DAT-02

## Description
A client's data is modified without their authorization between write and re-read.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The stored ciphertext is modified between write and re-read without the owner's authorization. | Content-hash addressing and AES-256-GCM AEAD detecting any modification on read. |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Shards are altered when served back to the client. | Authenticated libp2p transport and content-hash recompute on receipt, repair from intact shards. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Client-side AES-256-GCM encryption | T1565.001 | D3-MENCR | SC-28 |
| Encrypted / authenticated libp2p transport | T1565.002 | D3-MENCR | SC-8 |
| Content-hash recompute on receipt | T1565.002 | D3-FH | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1565.002 | — | SC-36 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
