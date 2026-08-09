# N-INT-STO-03 — Serving an old version (rollback)

- **Target**: Nodes
- **Category**: Integrity › Storage
- **Identifier**: N-INT-STO-03

## Description
The node deliberately serves a stale version of a shard or a manifest, regressing the state visible to the client.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The node returns an earlier revision (rollback) of a shard or manifest instead of the current state, manipulating the served data. | Ed25519-signed manifests carrying a version/sequence number: a rollback is detected by a regression of the signed number on the client side. |
| Use Alternate Authentication Material | T1550 | Replay analogue: re-serving a validly-signed past version amounts to replaying a stale authenticated state. | Signed nonces/sequence numbers and bounded-TTL tokens: an expired or out-of-sequence state is refused, breaking the replay. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned Ed25519-signed manifest | T1565.001 | D3-MAN | SI-7 |
| Anti-replay nonce/clock/seq + TTL | T1550 | — | SC-23 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1550 | — | AC-2, AC-3, AC-5, AC-6, CM-5, CM-6, IA-2 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
