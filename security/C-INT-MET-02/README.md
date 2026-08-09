# C-INT-MET-02 — Timestamp modification

- **Target**: Clients
- **Category**: Integrity › Metadata
- **Identifier**: C-INT-MET-02

## Description
The timestamps associated with the client's data are altered to distort the order or the freshness.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Indicator Removal: Timestomp | T1070.006 | The data timestamps are modified to distort the chronological order or the perceived freshness. | Signed clocks/nonces/sequence numbers (anti-replay) and an append-only chained audit log making any temporal rewrite detectable. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Altering the stored timestamp metadata aims to deceive the versioning logic. | Signed erasure metadata (`stripe.Descriptor`) and Ed25519-signed manifest fixing the expected order. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-replay nonce/clock/seq + TTL | T1070.006 | — | SC-23 |
| Append-only chained logs + signed seq | T1070.006 | — | AU-9 |
| Signed erasure metadata (stripe.Descriptor) | T1565.001 | D3-MAN | SI-7 |
| Versioned Ed25519-signed manifest | T1565.001 | D3-MAN | SI-7 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
