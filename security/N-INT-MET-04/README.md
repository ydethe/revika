# N-INT-MET-04 — Deletion of local events

- **Target**: Nodes
- **Category**: Integrity › Metadata
- **Identifier**: N-INT-MET-04

## Description
The node erases entries from its local metadata log to conceal past operations.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | The node deletes entries from its local metadata log to conceal operations it performed. | Append-only, signed and hash-chained audit logs: deleting an entry breaks the continuity of the chaining and is detected. |
| Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | Storage analogue: the node alters the logging that documents its own behaviour to escape audit. | Chained log replicated/verifiable by peers + signed sequence numbers making any omission visible as a gap in the sequence. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chained append-only logs + signed seq | T1070.002 | — | AU-9 |
| Cross-peer ledger corroboration | T1562.008 | — | AU-6 |
