# N-CONF-01 — Unauthorised reading of stored shards

- **Target**: Nodes
- **Category**: Confidentiality › Data
- **Identifier**: N-CONF-01

## Description
A node (or an attacker with access to its disk) tries to read the content of the shards it hosts to extract exploitable information, whereas it is only supposed to store opaque ciphertext addressed by content hash.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data from Local System | T1005 | The node directly reads the shard files present on its local disk to try to extract content. | Client-side AES-256-GCM encryption before emission: the node stores only opaque ciphertext, no key is present on the node side. |
| Data from Cloud Storage | T1530 | P2P analogue: extraction of data from a remote blob store hosting the shards. | ML-KEM-768 capability encapsulation (KEM-DEM, PQC): the decryption key stays on the User side and never reaches the store. |
| Automated Collection | T1119 | The node systematically collects the whole set of shards it hosts to analyse them. | Reed-Solomon erasure coding (`k=4`, `m=2`) spread across independent nodes: no node holds a whole file nor enough shards to reconstruct. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Client-side AES-256-GCM encryption | T1005 | D3-MENCR | SC-28 |
| ML-KEM-768 encapsulation (cap wrapping) | T1530 | D3-MENCR | SC-12 |
| Reed-Solomon coding k=4/m=2 + repair | T1119 | — | SC-36 |
| CTID controls (neo4j) | T1005 | — | AC-2, AC-3, AC-6, AC-16, AC-23, CM-12, CP-9, SA-8, SC-13, SC-38, SI-3, SI-4 |
| CTID controls (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SC-28, SI-4, SI-7, SI-12, SI-15 |
| CTID controls (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1005 | D3-EAL, D3-EDL, D3-FA, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-RAPA, D3-UAP, D3-UDTA | — |
| D3FEND techniques (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1119 | D3-OSM | — |
