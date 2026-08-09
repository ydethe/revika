# N-PROTO-01 — Injection of fake Gossip messages

- **Target**: Nodes
- **Category**: Protocol threats
- **Identifier**: N-PROTO-01

## Description
A node injects forged messages into the gossip channel to propagate false control information.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Forged control messages are injected into the gossip channel to alter the shared view of the network. | Ed25519 signature of every control message and rejection of unauthenticated messages, with anti-replay sequence numbers/nonces. |
| Application Layer Protocol | T1071 | The attacker abuses the libp2p gossip protocol to spread illegitimate control information. | Versioned libp2p protocols over an encrypted/authenticated transport, accepting only conforming messages emitted by authenticated peers. |
| Impersonation | T1656 | The fake messages pass themselves off as coming from an honest peer in order to be relayed. | Binding each message to the self-certifying pubkey of its emitter, preventing origin spoofing. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1565.002, T1656 | D3-MAN | AU-10 |
| Anti-replay nonce/clock/seq + TTL | T1565.002 | — | SC-23 |
| Versioned protocols + fail-closed | T1071 | — | SI-10 |
| Encrypted / authenticated libp2p transport | T1071 | D3-MENCR | SC-8 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| CTID controls (neo4j) | T1071 | — | AC-4, CA-7, CM-2, CM-6, CM-7, SC-7, SC-10, SC-20, SC-21, SC-22, SC-23, SC-31, SC-37, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1071 | D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
