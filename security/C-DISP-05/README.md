# C-DISP-05 — Saturating verifications

- **Target**: Clients
- **Category**: Availability
- **Identifier**: C-DISP-05

## Description
A client submits a volume of requests designed to saturate the nodes' verification mechanisms.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | The volume of requests aims to exhaust the nodes' verification mechanisms (hashes, signatures). | Rate-limit per-owner and apply the ledger quotas to cap the number of imposed verifications. |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | The attacker exploits the cost of verifications to maximize the load per request. | Require write admission by argon2id proof of work (difficulty ≥ that of the node), making it costly to submit mass verifications. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner rate-limiting (Ed25519 pubkey) | T1499.003 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1499.003 | — | SC-6 |
| Self-certifying PoW argon2id identity (anti-Sybil) | T1499.004 | — | SC-5 |
| CTID controls (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| CTID controls (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| D3FEND techniques (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
