# C-PROTO-04 — Exploitation of undefined behaviours

- **Target**: Clients
- **Category**: Protocol threats
- **Identifier**: C-PROTO-04

## Description
A client targets unspecified cases of the protocol to gain an advantage or provoke a fault.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | The client exercises unspecified cases of the protocol to trigger exploitable behaviour. | Default rejection (fail-closed) of any case not covered by the specification, versioned protocols and `ResourceManager` bounding the resources committed. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned protocols + fail-closed | T1499.004 | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | T1499.004 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
