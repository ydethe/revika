# N-INT-ID-02 — Identity duplication

- **Target**: Nodes
- **Category**: Integrity › Identity
- **Identifier**: N-INT-ID-02

## Description
A single cryptographic node identity is instantiated on several machines to blur accounting and placement.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | The same valid node identity is reused on several machines to skew accounting and placement. | Ledger rate-limiting and quotas keyed on the Ed25519 pubkey: a single identity remains capped regardless of the number of machines. |
| Botnet | T1584.005 | Analogue: several hosts operate under a single identity, forming a controlled set that masks its real distribution. | Placement based on shard diversity verified by hash and proof-of-possession probes, preventing a duplicated identity from simulating distributed redundancy. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner rate-limiting (Ed25519 pubkey) | T1078 | D3-ITF | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1078 | — | SC-6 |
| Network-measured placement diversity | T1584.005 | — | SC-36 |
| Probes + proof-of-possession challenges | T1584.005 | — | SI-7 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
