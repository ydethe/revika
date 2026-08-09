# N-DISP-05 — Network partition

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-05

## Description
A node or a network adversary causes or exploits a partition to isolate part of the network.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Network Denial of Service | T1498 | The adversary cuts or congests the links to isolate a subset of nodes from the rest of the network. | Kademlia DHT on the private `/revika` prefix with multi-node placement and libp2p NAT traversal, the Reed-Solomon redundancy allowing service from the majority partition. |
| Adversary-in-the-Middle | T1557 | The partition (an eclipse analogue) places the adversary as a cut-point between segments to control or block the exchanges. | Encrypted/authenticated libp2p transport and self-certified identities, preventing silent injection or interception despite the isolation. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + peer diversity | T1498 | — | SC-36 |
| Distributed placement across independent owners | T1498 | — | SC-36 |
| Reed-Solomon coding k=4/m=2 + repair | T1498 | — | SC-36 |
| Encrypted / authenticated libp2p transport | T1557 | D3-MENCR | SC-8 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1557 | — | SC-5 |
| CTID controls (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| CTID controls (neo4j) | T1557 | — | AC-3, AC-4, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-4, SC-7, SC-23, SC-46, SI-3, SI-4, SI-7, SI-12, SI-15 |
| D3FEND techniques (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
| D3FEND techniques (neo4j) | T1557 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
