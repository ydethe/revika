# C-INT-SIG-03 — Replay

- **Target**: Clients
- **Category**: Integrity › Signatures
- **Identifier**: C-INT-SIG-03

## Description
A legitimate signature is replayed in a different context to authorize an unintended operation.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | A replay analogue: a legitimate signed access token is reused in another context to authorize an operation. | Issuing signed access tokens with a limited lifetime (TTL) and bound to the context, with signed nonces/sequence numbers for anti-replay. |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Rebroadcasting a signed message in flight diverts its authority towards an unintended operation. | Including a clock/nonce in the signed message and transporting it over an encrypted/authenticated libp2p channel, rejecting any out-of-window or already-seen message. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-replay nonce/clock/seq + TTL | T1550.001, T1565.002 | — | SC-23 |
| Encrypted / authenticated libp2p transport | T1565.002 | D3-MENCR | SC-8 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
