# C-ECO-02 — Operation multiplication

- **Target**: Clients
- **Category**: Economic threats
- **Identifier**: C-ECO-02

## Description
A client repeats operations at large scale to gain a disproportionate economic advantage.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Repeating operations at large scale saturates the serving nodes. | Per-peer / per-owner rate-limiting (Ed25519 pubkey) and `ConnManager`/`ResourceManager` connection limits. |
| Resource Hijacking | T1496 | The client diverts a disproportionate volume of service to its own benefit. | Per-owner ledger quotas and TTL leases, with write admission under proof of work imposing a CPU cost per operation. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.003 | D3-ITF | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1499.003 | D3-NTF | SC-7 |
| Per-owner SQLite ledger + quotas/leases | T1496 | — | SC-6 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1496 | — | SC-5 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
