# C-CONF-04 — Collecting public information

- **Target**: Clients
- **Category**: Confidentiality
- **Identifier**: C-CONF-04

## Description
An attacker aggregates publicly available information (DHT announcements, public keys) to profile a client.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Gather Victim Network Information | T1590 | The attacker aggregates DHT announcements and observable peers to map the client's network footprint. | Discovery confined to the private `/revika` DHT prefix and minimization of public provider announcements. |
| Gather Victim Identity Information | T1589 | The public ML-KEM/Ed25519 pubkeys are collected to tie a client to its activities. | Self-certified libp2p identities dissociated from real-world identity, with possible rotation of storage identities. |
| Network Service Discovery | T1046 | DHT queries enumerate provider records to profile the data tied to a client. | Opaque hash addressing and per-owner rate-limiting on the Ed25519 pubkey slowing enumeration. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + peer diversity | T1590 | — | SC-36 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1589 | — | SC-5 |
| Content-hash addressing | T1046 | D3-FH | SI-7 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1046 | D3-ITF | SC-5 |
| CTID controls (neo4j) | T1046 | — | AC-4, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-7, SC-46, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1046 | D3-FA, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
