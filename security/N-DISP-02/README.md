# N-DISP-02 — Refusal to provide a shard

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-02

## Description
A node holds a shard but refuses to serve it to a legitimate client.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Service Stop | T1489 | P2P analogue: the node selectively interrupts the read service of a shard it nonetheless holds. | Reed-Solomon redundancy allowing reconstruction from any other subset of `k` shards without depending on the faulty node. |
| Inhibit System Recovery | T1490 | The refusal to serve aims to block reconstruction of the file on the client side. | Availability probes that reclassify the node as failed and trigger repair towards other nodes. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1489 | — | SC-36 |
| Probes + possession challenges | T1490 | — | SI-7 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
