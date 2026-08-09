# N-INT-MET-02 — Timestamp modification

- **Target**: Nodes
- **Category**: Integrity › Metadata
- **Identifier**: N-INT-MET-02

## Description
The node alters write or expiry timestamps in order to skew the ordering of events or the validity of leases.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Indicator Removal: Timestomp | T1070.006 | The node falsifies the write or lease-expiry timestamps to blur the real chronology of operations. | Client-signed clocks/nonces/sequence numbers and lease TTLs carried by signed tokens: an unsigned local timestamp is not a source of truth. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | By modifying expiry dates in the ledger, the node artificially extends or expires valid leases. | TTL leases anchored on signed, time-limited access tokens + revocation: a lease's validity is verified against the signature, not against the node's clock. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-replay nonce/clock/seq + TTL | T1070.006 | — | SC-23 |
| Short-TTL capabilities + revocation | T1565.001 | — | AC-3 |
| CTID controls (neo4j) | T1565.001 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
