# C-AC-05 — Circumventing a revocation

- **Target**: Clients
- **Category**: Access control
- **Identifier**: C-AC-05

## Description
A client whose access has been revoked circumvents the revocation to keep accessing the data.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | The client keeps presenting a token/capability despite the revocation. | Signed short-TTL tokens forcing frequent renewal, coupled with effective node-side revocation. |
| Valid Accounts | T1078 | The client reuses old credentials that are supposed to be invalidated. | `ConnectionGater` blocklist by the owner's Ed25519 pubkey and re-encapsulation (rotation) of shared capabilities after revocation. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Short-TTL capabilities + revocation | T1550.001 | — | AC-3 |
| ConnectionGater / ResourceManager / ConnManager | T1078 | D3-NTF | SC-7 |
| ML-KEM-768 encapsulation (cap wrapping) | T1078 | D3-MENCR | SC-12 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-28, SC-43, SI-4 |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
