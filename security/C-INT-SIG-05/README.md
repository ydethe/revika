# C-INT-SIG-05 — Use of a compromised key

- **Target**: Clients
- **Category**: Integrity › Signatures
- **Identifier**: C-INT-SIG-05

## Description
A compromised signing key continues to be accepted, allowing authorizations to be forged.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | The compromised owner key remains a valid identifier and is therefore still accepted by the nodes. | Maintaining a revocation list and allowing banning by Ed25519 pubkey (ConnectionGater / ledger), to stop honouring a compromised key. |
| Forge Web Credentials | T1606 | The attacker forges authorizations (capabilities/tokens) in the owner's name thanks to the compromised key. | Binding each authorization to revocable short-TTL signed capabilities, so that a forgery does not survive the revocation of the key. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | The tokens signed by the compromised key continue to open access. | Invalidating the leases/tokens of the compromised identity in the ledger and requiring a new PoW identity to re-admit writes. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Short-TTL capabilities + revocation | T1606 | — | AC-3 |
| ConnectionGater / ResourceManager / ConnManager | T1078 | D3-NTF | SC-7 |
| Per-owner SQLite ledger + quotas/leases | T1078, T1550.001 | — | SC-6 |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1550.001 | — | SC-5 |
| CTID controls (neo4j) | T1606 | — | AC-2, AC-5, AC-6, SC-17, SI-2 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-28, SC-43, SI-4 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1606 | D3-EAL, D3-EDL, D3-LFP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
