# N-DISP-06 — Blocking gossip

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-06

## Description
A node fails to propagate gossip messages, preventing the dissemination of control information.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The node blocks the relaying of gossip messages, stifling the dissemination of the network's control and health information. | Redundant propagation via the Kademlia DHT and multiple peers, so that a faulty relay does not cut off dissemination. |
| Network Denial of Service | T1498 | The non-propagation deprives a portion of the network of control updates, degrading coordination. | Availability probes detecting peers that do not relay and re-routing via multi-node placement. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + peer diversity | T1562.001 | — | SC-36 |
| Probes + possession challenges | T1498 | — | SI-7 |
| Distributed placement across independent owners | T1498 | — | SC-36 |
| CTID controls (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| D3FEND techniques (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
