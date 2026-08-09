# C-INT-MET-03 — False origin

- **Target**: Clients
- **Category**: Integrity › Metadata
- **Identifier**: C-INT-MET-03

## Description
A piece of data is presented as coming from an issuer that is not its own.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impersonation | T1656 | An actor impersonates a legitimate issuer to have a piece of data accepted under a false origin. | Ed25519 signature of the issuer verified on receipt and self-certifying storage identity by proof of work (argon2id) that is costly to impersonate. |
| Masquerading | T1036 | A piece of data presents itself under a falsified provenance to deceive the client. | Content-hash addressing and signed capabilities binding each piece of data to its verifiable owner. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1656, T1036 | D3-MAN | AU-10 |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1656 | — | SC-5 |
| Content-hash addressing | T1036 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
