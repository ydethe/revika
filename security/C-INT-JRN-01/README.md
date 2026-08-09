# C-INT-JRN-01 — Preventing an audit

- **Target**: Clients
- **Category**: Integrity › Journal
- **Identifier**: C-INT-JRN-01

## Description
An actor prevents the keeping or reading of the logs needed for an audit on the client side.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | The actor disables or hinders the logging mechanism, or blocks the audit event stream, to deprive the auditor of indicators. | Append-only, signed and chained (hash-chain) audit logs with sequential numbering: stopping, tampering or blocking creates a chain break or a sequence-number gap that is detectable. |
| Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | The local logs needed for the client audit are erased. | Making the log append-only and hash-chained, so that a deletion breaks the chain and is provable. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Append-only chained logs + signed seq | T1562.001, T1070.002 | — | AU-9 |
