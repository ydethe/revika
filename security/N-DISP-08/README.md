# N-DISP-08 — Refusal of maintenance

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-08

## Description
A node does not take part in the repair and re-encoding operations needed to maintain redundancy.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Inhibit System Recovery | T1490 | By abstaining from repairing and re-encoding, the node lets redundancy erode and hinders recovery. | Mandatory repair triggered by probes, operating on deterministic ciphertext via a signed repair grant, and redistributable to any other node. |
| Service Stop | T1489 | P2P analogue: the node interrupts its contribution to the stripe's maintenance service. | Signed erasure metadata (`stripe.Descriptor`) allowing a cooperative peer to regenerate the missing shards at their hash address. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon coding k=4/m=2 + repair | T1490 | — | SC-36 |
| Probes + possession challenges | T1490 | — | SI-7 |
| Signed repair grant | T1490 | D3-MAN | AC-3 |
| Signed erasure metadata (stripe.Descriptor) | T1489 | D3-MAN | SI-7 |
| Content-hash addressing | T1489 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
