# C-INT-MET-05 — False recipient list

- **Target**: Clients
- **Category**: Integrity › Metadata
- **Identifier**: C-INT-MET-05

## Description
The recipient list of a share is falsified, improperly adding or removing access.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The recipient list of a share is modified to improperly add or remove access. | Capabilities individually wrapped in ML-KEM-768 per recipient and an Ed25519-signed share list, with revocation managed by the owner. |
| Impersonation | T1656 | An attacker adds themselves as a legitimate recipient to gain non-consented access. | Wrapping the capability to the pubkey of the intended recipient only, an unintended access being unable to decrypt the key. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ML-KEM-768 wrapping (cap wrapping) | T1565.001, T1656 | D3-MENCR | SC-12 |
| Ed25519 signatures / capabilities | T1565.001 | D3-MAN | AU-10 |
| Short-TTL capabilities + revocation | T1565.001 | — | AC-3 |
| CTID controls (neo4j) | T1565.001 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
