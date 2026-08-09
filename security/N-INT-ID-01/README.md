# N-INT-ID-01 — Identity spoofing

- **Target**: Nodes
- **Category**: Integrity › Identity
- **Identifier**: N-INT-ID-01

## Description
A node passes itself off as another node (or as an owner) in order to benefit from its rights or its reputation.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impersonation | T1656 | The node claims to be another node or an owner to inherit its rights or its reputation. | Self-certified libp2p identities and Ed25519 signatures: every message/write is authenticated by the real pubkey, not spoofable without the private key. |
| Valid Accounts | T1078 | Analogue: the attacker exploits a legitimate peer's identity to access its rights on the network. | Encrypted/authenticated libp2p transport and signed capabilities bound to the holder's pubkey, with ledger quotas and leases indexed on the Ed25519 owner. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1656, T1078 | D3-MAN | AU-10 |
| Encrypted / authenticated libp2p transport | T1078 | D3-MENCR | SC-8 |
| Per-owner SQLite ledger + quotas/leases | T1078 | — | SC-6 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
