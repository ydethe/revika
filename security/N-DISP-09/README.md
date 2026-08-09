# N-DISP-09 — Strategic disconnection

- **Target**: Nodes
- **Category**: Availability
- **Identifier**: N-DISP-09

## Description
A node disconnects at critical moments (audits, repairs) to escape its obligations while remaining nominally a member.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The node disconnects during audits/repairs to evade the collection of retention evidence. | Append-only, signed and hash-chained audit logs that timestamp the unavailability during critical windows, exploitable after the fact. |
| Service Stop | T1489 | The node suspends its service at audit/repair moments while remaining nominally a member. | Availability probes repeated at unpredictable times and repair towards available peers thanks to Reed-Solomon redundancy. |
| Inhibit System Recovery | T1490 | The absence during repairs prevents the regeneration of the stripe's redundancy. | Signed repair grant allowing other nodes to regenerate the shards without the absent participant. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1562.001 | — | AU-9 |
| Probes + proof-of-possession challenges | T1489 | — | SI-7 |
| Reed-Solomon coding k=4/m=2 + repair | T1489 | — | SC-36 |
| Signed repair grant | T1490 | D3-MAN | AC-3 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
