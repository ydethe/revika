# C-CONF-02 — Metadata correlation

- **Target**: Clients
- **Category**: Confidentiality
- **Identifier**: C-CONF-02

## Description
Cross-referencing client-side metadata (manifests, identifiers, sizes) makes it possible to link data or users.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data from Information Repositories | T1213 | The attacker uses manifests and stripe indexes as an information repository to correlate data and users. | Client-side encryption of manifests and ML-KEM-768 capability encapsulation, with the non-confidential erasure metadata (`stripe.Descriptor`) minimized. |
| Automated Collection | T1119 | Automated cross-referencing of shard identifiers and sizes makes it possible to link datasets together. | Content-hash addressing and shards of a size normalized by chunking, reducing exploitable correlations. |
| Gather Victim Identity Information | T1589 | The Ed25519/ML-KEM pubkeys associated with manifests are used to link users to their data. | Self-certified libp2p identities unlinked from real-world identity, capabilities encapsulated per recipient without exposing the access list. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Client-side AES-256-GCM encryption | T1213 | D3-MENCR | SC-28 |
| ML-KEM-768 encapsulation (cap wrapping) | T1213 | D3-MENCR | SC-12 |
| Signed erasure metadata (stripe.Descriptor) | T1213 | D3-MAN | SI-7 |
| Content-hash addressing | T1119 | D3-FH | SI-7 |
| Fixed-size chunking / shard normalization | T1119 | — | SC-4 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1589 | — | SC-5 |
| CTID controls (neo4j) | T1213 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-21, AC-23, CA-7, CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, IA-2, IA-4, IA-8, RA-5, SC-37, SI-4 |
| CTID controls (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-36, SI-4, SI-12 |
| D3FEND techniques (neo4j) | T1213 | D3-EAL, D3-EDL, D3-ITF, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-RAPA, D3-UAP, D3-UDTA | — |
| D3FEND techniques (neo4j) | T1119 | D3-OSM | — |
