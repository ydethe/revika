# C-ECO-04 — Attempt to obtain resources for free

- **Target**: Clients
- **Category**: Economic threats
- **Identifier**: C-ECO-04

## Description
A client seeks to consume storage and bandwidth without paying the expected consideration.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Resource Hijacking | T1496 | The client consumes storage and bandwidth without providing the expected consideration. | Write admission under proof of work (CPU cost per identity), per-owner ledger quotas and rate-limiting/`ConnManager` bounding per-peer bandwidth. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1496 | — | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1496 | — | SC-6 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1496 | D3-ITF | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1496 | D3-NTF | SC-7 |
