# C-INT-SIG-02 — Signature of a different content

- **Target**: Clients
- **Category**: Integrity › Signatures
- **Identifier**: C-INT-SIG-02

## Description
A valid signature is presented as covering content that it does not actually cover.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | A falsified content is disguised as legitimately signed content by reusing a valid signature outside its scope. | Signing not the raw content but the content hash of the shard, so that the signature is valid only for the exact addressed object. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The signature↔content link is diverted to pass modified data off as authenticated. | Recomputing and comparing the content hash on verification, any discrepancy between the served content and the signed hash being rejected. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1036 | D3-MAN | AU-10 |
| Content-hash addressing | T1036 | D3-FH | SI-7 |
| Content-hash recompute on receipt | T1565.001 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
