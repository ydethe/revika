# N-ORG-GEO-01 — Falsifying its location

- **Target**: Nodes
- **Category**: Organisational threats › Geolocation
- **Identifier**: N-ORG-GEO-01

## Description
A node declares an erroneous geographic position to satisfy distribution constraints.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | The node self-declares a falsified geographic position attribute to satisfy the distribution constraints. | Do not trust self-declared geolocation: derive the position via latency/topology probes and observed subnet/AS at the libp2p level. |
| Transmitted Data Manipulation | T1565.002 | Analogue: the location metadata transmitted to the placement policy is manipulated in transit by the emitting node. | Placement policy based on verifiable network measurements rather than declarative metadata, and diversity keyed on the Ed25519 pubkey. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Network-measured placement diversity | T1036, T1565.002 | — | SC-36 |
| Placement spread over independent owners | T1565.002 | — | SC-36 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
