# C-INT-SIG-01 — Double signature

- **Target**: Clients
- **Category**: Integrity › Signatures
- **Identifier**: C-INT-SIG-01

## Description
The same content receives two contradictory signatures in order to create an ambiguity of authority.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impersonation | T1656 | Two competing Ed25519 signatures blur the identity of the legitimate author of the content. | Making the per-owner SQLite ledger (ownership index bound to the Ed25519 pubkey) the single source of authority, refusing any second claim on the same content. |
| Masquerading | T1036 | The attacker presents their signature as equivalent to the owner's to usurp authority over the content. | Binding each signature to an unambiguous signed capability (manifest location + ML-KEM-768 wrapped key) attached to a single owner. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The coexistence of two signatures alters the stored truth about the integrity and provenance of the content. | Verifying each shard by recomputing the content hash, hash addressing making any contradictory claim detectable and rejectable. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Per-owner SQLite ledger + quotas/leases | T1656 | — | SC-6 |
| Ed25519 signatures / capabilities | T1036 | D3-MAN | AU-10 |
| ML-KEM-768 wrapping (cap wrapping) | T1036 | D3-MENCR | SC-12 |
| Content-hash recompute on receipt | T1565.001 | D3-FH | SI-7 |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
