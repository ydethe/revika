# N-INT-ID-03 — Private key theft

- **Target**: Nodes
- **Category**: Integrity › Identity
- **Identifier**: N-INT-ID-03

## Description
A node's identity private key is stolen, allowing the attacker to act under that identity.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Unsecured Credentials | T1552 | The node's identity private key is stolen where it is stored in the clear on the host. | Restricted key storage under `.revika/keys` with strict permissions; stdlib crypto isolation and keys never transmitted off the machine. |
| Steal or Forge Authentication Certificates | T1649 | The attacker obtains the identity cryptographic material to sign as the legitimate node. | Identity rotation/revocation and PoW re-grinding (argon2id) of a new self-certifying identity, invalidating use of the stolen key. |
| Valid Accounts | T1078 | Armed with the stolen key, the attacker acts under the node's authentic identity on the network. | Per-owner TTL ledger leases and quotas + `ConnectionGater` blocklist, limiting abuse and allowing the compromised identity to be excluded. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Client-side key isolation (.revika/keys) | T1552 | — | SC-12 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1649 | — | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1078 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1078 | D3-NTF | SC-7 |
| CTID controls (neo4j) | T1552 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, IA-2, IA-3, IA-4, IA-5, RA-5, SA-11, SA-15, SC-4, SC-7, SC-28, SI-2, SI-4, SI-7, SI-12, SI-15 |
| CTID controls (neo4j) | T1649 | — | IA-2, IA-5 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-28, SC-43, SI-4 |
| D3FEND techniques (neo4j) | T1552 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
