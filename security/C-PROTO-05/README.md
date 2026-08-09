# C-PROTO-05 — False declaration of capabilities

- **Target**: Clients
- **Category**: Protocol threats
- **Identifier**: C-PROTO-05

## Description
A client advertises capabilities it does not possess in order to negotiate an unsuitable service.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | The client presents itself with false capabilities during service negotiation. | Cryptographically verified negotiation (self-certified Ed25519/PoW capabilities and identity), with unproven claims rejected. |
| Impersonation | T1656 | The client spoofs a capability profile to obtain undue treatment. | Write admission conditioned on a proof of work (argon2id) and an identity bound to the pubkey, making spoofing costly and verifiable. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1036 | D3-MAN | AU-10 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1656 | — | SC-5 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
