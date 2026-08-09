# N-CONF-04 — Observation of network flows

- **Target**: Nodes
- **Category**: Confidentiality › Data
- **Identifier**: N-CONF-04

## Description
Analysing a node's inbound/outbound traffic (volumes, destinations, timing) reveals information about the exchanges even when the transported content is encrypted.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Network Sniffing | T1040 | Capture and analysis of the node's inbound/outbound traffic (volumes, timing) despite encrypted content. | Encrypted and authenticated libp2p transport carrying only opaque ciphertext addressed by hash, with no plaintext nor exploitable file metadata. |
| Gather Victim Network Information | T1590 | Collection of destinations and throughputs to map the node's exchanges. | libp2p NAT traversal and dispersion of shards by erasure coding across independent nodes reducing flow ↔ file correlation. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Encrypted / authenticated libp2p transport | T1040 | D3-MENCR | SC-8 |
| Reed-Solomon coding k=4/m=2 + repair | T1590 | — | SC-36 |
| Distributed placement across independent owners | T1590 | — | SC-36 |
| CTID controls (neo4j) | T1040 | — | AC-16, AC-17, AC-18, AC-19, CM-7, IA-2, IA-5, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1040 | D3-OSM | — |
