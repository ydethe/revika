# C-COL-03 — Key sharing

- **Target**: Clients
- **Category**: Collusion
- **Identifier**: C-COL-03

## Description
Clients share keys to improperly pool accesses or identities.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Clients share keys to pool accesses outside the intended framework. | Sharing designed only through ML-KEM-768 encapsulation to the recipient's pubkey, revocable TTL capabilities and key rotation. |
| Valid Accounts | T1078 | Clients pool a single storage identity/key to act under a shared identity. | Self-certifying identity bound to a unique Ed25519 key via proof of work, with a signed, chained audit log tracing usage. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ML-KEM-768 encapsulation (cap wrapping) | T1550 | D3-MENCR | SC-12 |
| Short-TTL capabilities + revocation | T1550 | — | AC-3 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1078 | — | SC-5 |
| Chained append-only logs + signed seq | T1078 | — | AU-9 |
| CTID controls (neo4j) | T1550 | — | AC-2, AC-5, AC-6, CM-5, CM-6, IA-2 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| D3FEND techniques (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
