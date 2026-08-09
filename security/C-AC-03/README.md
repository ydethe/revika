# C-AC-03 — Forged token

- **Target**: Clients
- **Category**: Access control
- **Identifier**: C-AC-03

## Description
A client presents a forged access token to obtain a service.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Forge Web Credentials | T1606 | The client fabricates an access token that no legitimate authority issued (the P2P analogue of a forged web credential). | Ed25519-signed tokens and capabilities: any invalid signature is rejected, and forging requires the owner's private key. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | The client submits the forged token to the node to obtain the service. | Systematic node-side verification of the token signature before any service, backed by the ownership ledger. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1606 | D3-MAN | AU-10 |
| Per-owner SQLite ledger + quotas/leases | T1550.001 | — | SC-6 |
| CTID controls (neo4j) | T1606 | — | AC-2, AC-3, AC-5, AC-6, SC-17, SI-2 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1606 | D3-EAL, D3-EDL, D3-LFP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
