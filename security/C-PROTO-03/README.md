# C-PROTO-03 — Old protocol version

- **Target**: Clients
- **Category**: Protocol threats
- **Identifier**: C-PROTO-03

## Description
A client forces the use of an obsolete protocol version to benefit from its weaknesses.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Weaken Encryption | T1600 | The client attempts a downgrade to a version with weakened cryptographic or protocol guarantees. | Versioned libp2p protocols whose negotiation refuses deprecated versions, over an encrypted/authenticated transport enforcing AES-256-GCM and ML-KEM-768. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned protocols + fail-closed | T1600 | — | SI-10 |
| Encrypted / authenticated libp2p transport | T1600 | D3-MENCR | SC-8 |
