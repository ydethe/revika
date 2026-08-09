# N-ECO-02 — Participating only in remunerative operations

- **Target**: Nodes
- **Category**: Economic threats
- **Identifier**: N-ECO-02

## Description
A node only handles profitable tasks and neglects unpaid obligations (repair, cold serving).

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Inhibit System Recovery | T1490 | By neglecting mandatory repair, the node prevents the regeneration of shards and compromises the restoration of redundancy. | Mandatory repair driven by a signed grant on deterministic ciphertext, executed from other nodes via Reed-Solomon erasure coding (`k=4`, `m=2`) without depending on the failing node. |
| Service Stop | T1489 | The node selectively refuses unpaid operations (cold serving), effectively stopping the service on part of the data. | Availability probes detecting non-service, TTL leases in the ledger and re-placement of shards towards nodes honouring their commitments. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1490 | — | SC-36 |
| Signed repair grant | T1490 | D3-MAN | AC-3 |
| Probes + proof-of-possession challenges | T1489 | — | SI-7 |
| Per-owner SQLite ledger + quotas/leases | T1489 | — | SC-6 |
| Placement spread across independent owners | T1489 | — | SC-36 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
