# N-AC-05 — Falsifying a requester's identity

- **Target**: Nodes
- **Category**: Access control
- **Identifier**: N-AC-05

## Description
A node assigns a request a different requester identity to bypass access controls.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impersonation | T1656 | A request is assigned a spoofed requester identity in order to benefit from another owner's rights. | Cryptographic binding of each request to a self-certifying Ed25519 pubkey, the identity only being assertable by proving possession of the private key. |
| Masquerading | T1036 | The node presents a falsified requester identity to pass the access controls. | Signed access tokens bound to the requester's identity and verified at the source, preventing any identity reassignment on the node side. |
| Forge Web Credentials | T1606 | A proof of requester identity is forged to pass as an authorised owner. | Authentication by Ed25519 signature over a nonce, unforgeable without the private key, rather than by a declarative identifier. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1656, T1036, T1606 | D3-MAN | AU-10 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1606 | — | AC-2, AC-3, AC-5, AC-6, SC-17, SI-2 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1606 | D3-EAL, D3-EDL, D3-LFP, D3-UAP | — |
