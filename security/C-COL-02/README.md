# C-COL-02 — Collusion with nodes

- **Target**: Clients
- **Category**: Collusion
- **Identifier**: C-COL-02

## Description
A client colludes with nodes to obtain preferential treatment or deceive audits.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Trusted Relationship | T1199 | The client exploits an arrangement with nodes to obtain preferential treatment. | "Dumb", untrusted node model: they see only opaque ciphertext addressed by hash, and cannot grant any privilege over the content. |
| Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | The collusion aims to falsify or hide the nodes' audit logs. | Signed, chained (hash-chain) append-only audit logs that detect rewriting/omission, and independent shard verification by recomputing the hash. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| "Dumb/untrusted" node + User-side re-verification | T1199 | — | SA-8 |
| Chained append-only logs + signed seq | T1562.008 | — | AU-9 |
| Hash recomputation on receipt | T1562.008 | D3-FH | SI-7 |
| CTID controls (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| D3FEND techniques (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
