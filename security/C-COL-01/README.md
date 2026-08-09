# C-COL-01 — Collusion between clients

- **Target**: Clients
- **Category**: Collusion
- **Identifier**: C-COL-01

## Description
Several clients coordinate their actions to circumvent limits or distort mechanisms.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Create Account | T1136 | The actors create several coordinated client identities to exceed individual limits (Sybil analogue). | Self-certifying storage identity by proof of work (argon2id), making it costly to multiply identities. |
| Establish Accounts | T1585 | Identities are established in concert to distort mechanisms that count per actor. | Quotas and rate-limiting applied per-owner on the Ed25519 pubkey, independently of the number of identities. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1136 | — | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1585 | — | SC-6 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1585 | D3-ITF | SC-5 |
| CTID controls (neo4j) | T1136 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-20, CM-5, CM-6, CM-7, IA-2, IA-5, SC-7, SC-46, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1136 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
