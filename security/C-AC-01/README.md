# C-AC-01 — Access without authorization

- **Target**: Clients
- **Category**: Access control
- **Identifier**: C-AC-01

## Description
A client attempts to access data for which it holds no valid capability.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data from Cloud Storage | T1530 | The client seeks to read stored shards without a valid capability (the P2P analogue of cloud storage). | Client-side encryption before transmission: nodes see only opaque ciphertext, unusable without the ML-KEM-768 encapsulated key. |
| Brute Force | T1110 | The client tries to guess or force an access capability/key. | Ed25519-signed capabilities required and high-entropy AES-256-GCM keys make forcing infeasible; read admission is conditioned on a verified capability. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Client-side AES-256-GCM encryption | T1530 | D3-MENCR | SC-28 |
| ML-KEM-768 encapsulation (cap wrapping) | T1530 | D3-MENCR | SC-12 |
| Ed25519 signatures / capabilities | T1110 | D3-MAN | AU-10 |
| CTID controls (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SI-4, SI-7, SI-12, SI-15 |
| CTID controls (neo4j) | T1110 | — | AC-2, AC-3, AC-5, AC-6, AC-7, AC-20, CA-7, CM-2, CM-6, IA-2, IA-4, IA-5, IA-11, SI-4 |
| D3FEND techniques (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1110 | D3-AL, D3-EAL, D3-EDL, D3-LFP, D3-OSM, D3-UAP | — |
