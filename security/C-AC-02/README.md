# C-AC-02 — Reuse of an expired right

- **Target**: Clients
- **Category**: Access control
- **Identifier**: C-AC-02

## Description
A client reuses a right or token whose validity has expired.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | The client replays an access token whose TTL has elapsed (the P2P analogue of replaying an application token). | Signed access tokens with a limited time-to-live (TTL) verified on every request, with node-side signed nonces/clocks for anti-replay. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Short-TTL capabilities + revocation | T1550.001 | — | AC-3 |
| Nonce/clock/seq anti-replay + TTL | T1550.001 | — | SC-23 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
