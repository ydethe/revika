# N-INT-PRE-02 — Reuse of old proofs

- **Target**: Nodes
- **Category**: Integrity › Proofs
- **Identifier**: N-INT-PRE-02

## Description
A node replays a valid storage proof issued previously to claim it still holds the data.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Replay analogue: the node re-issues an already-valid storage proof to appear to still be a custodian. | Proof-of-possession challenges with a fresh random nonce and a TTL, signed, making any earlier proof unusable for a new challenge. |
| Transmitted Data Manipulation | T1565.002 | The replayed proof skews the availability state transmitted to the verifier. | Binding of each proof to a unique, timestamped and signed challenge (Ed25519), verified then rejected if already consumed in the ledger. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Probes + proof-of-possession challenges | T1550 | — | SI-7 |
| Anti-replay nonce/clock/seq + TTL | T1565.002 | — | SC-23 |
| CTID controls (neo4j) | T1550 | — | AC-2, AC-3, AC-5, AC-6, CM-5, CM-6, IA-2 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
