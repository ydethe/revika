# C-INT-SIG-04 — Stolen signature

- **Target**: Clients
- **Category**: Integrity › Signatures
- **Identifier**: C-INT-SIG-04

## Description
A signature, or the key that produces it, is stolen and reused by a third party.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Unsecured Credentials | T1552 | The poorly-protected Ed25519 signing key on the client's machine is stolen. | Storing the client-side keys in `.revika/keys` with restricted permissions and advocating protected storage, reducing the exposure of the owner key. |
| Steal Application Access Token | T1528 | A signed token or capability is stolen and then replayed by a third party. | Limiting the lifetime (TTL) of signed tokens/leases and allowing their revocation, bounding the exploitation window of a theft. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | The third party reuses the stolen signature/key to pass themselves off as the owner. | Conditioning the admission of writes on an argon2id proof of work, so that displacing and re-minting a banned identity costs CPU. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Client-side key isolation (.revika/keys) | T1552 | — | SC-12 |
| Short-TTL capabilities + revocation | T1528 | — | AC-3 |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1550.001 | — | SC-5 |
| CTID controls (neo4j) | T1552 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, IA-2, IA-3, IA-4, IA-5, RA-5, SA-11, SA-15, SC-4, SC-7, SC-28, SI-2, SI-4, SI-7, SI-12, SI-15 |
| CTID controls (neo4j) | T1528 | — | AC-2, AC-4, AC-5, AC-6, AC-10, CA-7, CM-2, CM-5, CM-6, IA-2, IA-4, IA-5, IA-8, RA-5, SA-11, SA-15, SI-4 |
| CTID controls (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1552 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1528 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1550.001 | D3-OSM | — |
