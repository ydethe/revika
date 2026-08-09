# C-PROTO-01 — Protocol non-compliance

- **Target**: Clients
- **Category**: Protocol threats
- **Identifier**: C-PROTO-01

## Description
A client deliberately deviates from the expected protocol to cause abnormal behaviour in the nodes.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | The protocol deviation aims to cause a fault or abnormal behaviour in the node. | Versioned libp2p protocols with strict message validation (fail-closed) and `ResourceManager`/`ConnManager` bounding the impact of a faulty peer. |
| Application Layer Protocol | T1071 | The client diverts the revika application protocol from its intended use. | Versioned and authenticated libp2p stream protocols, rejecting any frame not compliant with the negotiated version contract. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned protocols + fail-closed | T1499.004, T1071 | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | T1499.004 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1071 | — | AC-4, CA-7, CM-2, CM-6, CM-7, SC-7, SC-10, SC-20, SC-21, SC-22, SC-23, SC-31, SC-37, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1071 | D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
