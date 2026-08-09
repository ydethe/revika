# N-PROTO-06 — Disabling verifications

- **Target**: Nodes
- **Category**: Protocol threats
- **Identifier**: N-PROTO-06

## Description
A node locally disables the compliance checks it is supposed to apply.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The node locally disables the compliance checks (authorisation, quotas, integrity) it should apply. | Security independent of the node's goodwill: client-side encryption, hash addressing and Reed-Solomon erasure coding + repair neutralise a node that relaxes its checks. |
| Exploitation for Defense Evasion | T1211 | Disabling the checks lets the node bypass the protocol's expected defences. | Critical verifications replayed on the User side (hash recomputation, validation of signed capabilities) rather than delegated to the node. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| "Dumb/untrusted" node + User-side re-verification | T1562.001, T1211 | — | SA-8 |
| Reed-Solomon k=4/m=2 coding + repair | T1562.001 | — | SC-36 |
| Recompute the hash on receipt | T1562.001, T1211 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1211 | — | AC-4, AC-6, CA-7, CM-2, CM-6, CM-8, RA-5, RA-10, SC-2, SC-3, SC-7, SC-18, SC-26, SC-29, SC-30, SC-35, SC-39, SI-2, SI-3, SI-4, SI-5 |
| D3FEND techniques (neo4j) | T1211 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
