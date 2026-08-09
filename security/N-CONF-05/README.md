# N-CONF-05 — Inference of relations between users

- **Target**: Nodes
- **Category**: Confidentiality › Data
- **Identifier**: N-CONF-05

## Description
By correlating owners, share recipients and placement patterns, an observer reconstitutes the graph of relations between users.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Gather Victim Identity Information | T1589 | Correlation of owners and share recipients to identify users and their links. | Read capabilities encapsulated in ML-KEM-768 to the recipient's pubkey: no cleartext recipient appears on the node side. |
| Gather Victim Org Information | T1591 | Reconstitution of the relation graph from the observed placement patterns. | Shares and placements mediated by signed capabilities; the node only handles opaque Ed25519 pubkeys with no relation semantics. |
| Automated Collection | T1119 | Systematic collection of owners/recipients/placements to build the social graph. | Per-owner rate-limiting and identities self-certified by proof of work (argon2id, `internal/cap/pow.go`) slowing accumulation and enumeration. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ML-KEM-768 encapsulation (cap wrapping) | T1589 | D3-MENCR | SC-12 |
| Ed25519 signatures / capabilities | T1591 | D3-MAN | AU-10 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1119 | D3-ITF | SC-5 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1119 | — | SC-5 |
| CTID controls (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-4, SC-36, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1119 | D3-OSM | — |
