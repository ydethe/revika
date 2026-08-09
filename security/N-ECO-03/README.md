# N-ECO-03 — Leaving after reward

- **Target**: Nodes
- **Category**: Economic threats
- **Identifier**: N-ECO-03

## Description
A node collects rewards then leaves the network without honouring its retention commitments.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Destruction | T1485 | Analogue: the node's abrupt departure makes the shards it held unavailable ("destroyed"). | Reed-Solomon erasure coding (any `k` reconstruct) + mandatory repair regenerating lost shards on deterministic ciphertext reproducing their content address. |
| Service Stop | T1489 | The node ceases all service after cashing in, interrupting access to the hosted data. | TTL leases and availability probes detecting the exit, triggering re-placement towards other owners before redundancy expires. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1485 | — | SC-36 |
| Content-hash addressing | T1485 | D3-FH | SI-7 |
| Per-owner SQLite ledger + quotas/leases | T1489 | — | SC-6 |
| Probes + proof-of-possession challenges | T1489 | — | SI-7 |
| Placement spread across independent owners | T1489 | — | SC-36 |
| CTID controls (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| D3FEND techniques (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
