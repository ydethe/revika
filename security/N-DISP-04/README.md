# N-DISP-04 — Deliberate slowdown

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-04

## Description
A node deliberately degrades its response times to harm overall performance without declaring itself offline.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service | T1499 | P2P analogue: the node deliberately degrades its service latency without withdrawing, harming perceived availability. | Availability probes measuring latency, with reads failing over to faster peers thanks to Reed-Solomon redundancy. |
| Service Exhaustion Flood | T1499.002 | The slowdown simulates a service saturation to make the responses practically unusable. | Per-peer / per-owner rate-limiting (keyed on the Ed25519 pubkey) and the `ResourceManager`/`ConnManager` of `internal/net/defense.go` bounding the impact of a slow peer. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + possession challenges | T1499 | — | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1499 | — | SC-36 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.002 | D3-ITF | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1499.002 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1499 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1499.002 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1499.002 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
