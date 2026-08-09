# N-PROTO-03 — Redirection to fake peers

- **Target**: Nodes
- **Category**: Protocol threats
- **Identifier**: N-PROTO-03

## Description
A node directs discovery requests towards peers controlled by the attacker.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Adversary-in-the-Middle | T1557 | Discovery responses are poisoned to redirect the victim towards peers controlled by the attacker. | Verification by content-hash addressing of the shards obtained regardless of the peer, a malicious peer being unable to provide valid ciphertext. |
| Rogue Domain Controller | T1207 | The announced fake peers present themselves as legitimate providers of the sought data, as a P2P analogue of an illegitimate controller. | Reed-Solomon erasure coding (`k=4`, `m=2`) allowing reconstruction from other peers and mandatory repair bypassing failing peers. |
| Acquire Infrastructure: Server | T1583.004 | The attacker deploys dedicated nodes to capture discovery requests. | Self-certifying PoW identities and `ConnectionGater` with a per-peer/subnet blocklist limiting the insertion of hostile nodes. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash addressing | T1557 | D3-FH | SI-7 |
| Reed-Solomon k=4/m=2 coding + repair | T1207 | — | SC-36 |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1583.004 | — | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1583.004 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1557 | — | AC-3, AC-4, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-4, SC-7, SC-8, SC-23, SC-46, SI-3, SI-4, SI-12, SI-15 |
| D3FEND techniques (neo4j) | T1557 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
