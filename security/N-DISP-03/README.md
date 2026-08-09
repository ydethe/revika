# N-DISP-03 — Refusal to respond

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-03

## Description
A node ignores incoming requests, behaving as unreachable while remaining nominally present.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service | T1499 | P2P analogue: the node makes its own service endpoint unavailable by no longer acknowledging any request. | Availability probes and automatic repair towards responsive nodes, the Reed-Solomon redundancy absorbing the loss of the silent node. |
| Service Stop | T1489 | The node remains a member of the network but stops processing incoming application flows. | Lease/quota tracking in the SQLite ledger and downgrading of the unreachable node in favour of placement on active peers. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + possession challenges | T1499 | — | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1499 | — | SC-36 |
| Per-owner SQLite ledger + quotas/leases | T1489 | — | SC-6 |
| Distributed placement across independent owners | T1489 | — | SC-36 |
| CTID controls (neo4j) | T1499 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| D3FEND techniques (neo4j) | T1499 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
