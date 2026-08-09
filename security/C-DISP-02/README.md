# C-DISP-02 — Connection multiplication

- **Target**: Clients
- **Category**: Availability
- **Identifier**: C-DISP-02

## Description
A client opens a large number of connections to exhaust the nodes' connection resources.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Service Exhaustion Flood | T1499.002 | Multiplying connections exhausts the nodes' connection service. | Cap connections via `ConnManager` (low/high bounds, grace period) in `internal/net/defense.go`. |
| Endpoint Denial of Service: OS Exhaustion Flood | T1499.001 | The large number of connections exhausts the node's system resources (descriptors, memory). | Enforce the libp2p `ResourceManager` limits and ban by peer/subnet via `ConnectionGater`. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1499.001, T1499.002 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1499.001 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1499.002 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.001 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1499.002 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
