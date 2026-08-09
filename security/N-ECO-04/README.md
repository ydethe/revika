# N-ECO-04 — Clandestinely outsourcing storage

- **Target**: Nodes
- **Category**: Economic threats
- **Identifier**: N-ECO-04

## Description
A node secretly delegates storage to a third party or a cloud, breaking the assumptions of independence and location.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Trusted Relationship | T1199 | The node relies on a hidden third party (host, cloud) to meet its commitments, breaking the independence assumption. | Confidentiality preserved whatever happens: the third party only sees opaque ciphertext (client-side AES-256-GCM encryption); placement diversity measured by network probes, not by declaration. |
| Proxy | T1090 | Analogue: the node secretly relays shards towards an external backend instead of storing them locally. | Proof-of-possession probes recomputing the content hash and latency/topology measurement to detect a remote backend; quota and ownership index kept by the ledger. |
| Data from Cloud Storage | T1530 | Analogue: the entrusted data ends up stored on a third-party cloud service, outside the revika threat model. | Client-side encryption and ML-KEM-768 capability wrapping: even if exfiltrated to a cloud, the shard remains unusable without the key held on the User side. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Client-side AES-256-GCM encryption | T1199, T1530 | D3-MENCR | SC-28 |
| Network-measured placement diversity | T1199 | — | SC-36 |
| Probes + proof-of-possession challenges | T1090 | — | SI-7 |
| Per-owner SQLite ledger + quotas/leases | T1090 | — | SC-6 |
| ML-KEM-768 wrapping (cap wrapping) | T1530 | D3-MENCR | SC-12 |
| CTID controls (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| CTID controls (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SI-4, SI-7, SI-12, SI-15 |
| CTID controls (neo4j) | T1090 | — | AC-3, AC-4, CA-7, CM-2, CM-6, CM-7, SC-7, SC-8, SI-3, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1090 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
