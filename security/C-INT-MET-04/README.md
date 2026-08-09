# C-INT-MET-04 — Version manipulation

- **Target**: Clients
- **Category**: Integrity › Metadata
- **Identifier**: C-INT-MET-04

## Description
The version number or version chain of a piece of content is manipulated to pass one version off as another.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The stored version number or version chain is modified to pass one version off as another. | Ed25519-signed manifest per version and content-hash pointers, any manipulation invalidating the signature. |
| Use Alternate Authentication Material | T1550 | An earlier version is replayed as if it were current (a replay/rollback analogue). | Signed sequence numbers/nonces (anti-replay) and token TTLs rejecting the presentation of a stale version. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned Ed25519-signed manifest | T1565.001 | D3-MAN | SI-7 |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| Anti-replay nonce/clock/seq + TTL | T1550 | — | SC-23 |
| Short-TTL capabilities + revocation | T1550 | — | AC-3 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1550 | — | AC-2, AC-5, AC-6, CM-5, CM-6, IA-2 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
