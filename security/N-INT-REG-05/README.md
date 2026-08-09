# N-INT-REG-05 — Event replay

- **Target**: Nodes
- **Category**: Integrity › Registry
- **Identifier**: N-INT-REG-05

## Description
A node re-emits already-valid registry events so they are counted several times.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Replay analogue: the node reuses an already-valid signed event to have it recounted. | Per-entry signed nonces, timestamps and sequence numbers, with ledger-side deduplication to reject any replay. |
| Transmitted Data Manipulation | T1565.002 | The re-emission falsifies the accounting by inflating the count of events transmitted to the registry. | Idempotence of content-hash-addressed writes; versioned libp2p protocols bind each message to a unique, non-replayable identifier. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-replay nonce/clock/seq + TTL | T1550 | — | SC-23 |
| Content-hash addressing | T1565.002 | D3-FH | SI-7 |
| Versioned protocols + fail-closed | T1565.002 | — | SI-10 |
| CTID controls (neo4j) | T1550 | — | AC-2, AC-3, AC-5, AC-6, CM-5, CM-6, IA-2 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| D3FEND techniques (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
