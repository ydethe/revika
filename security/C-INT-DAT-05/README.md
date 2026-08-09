# C-INT-DAT-05 — Injection of malicious data

- **Target**: Clients
- **Category**: Integrity › Data
- **Identifier**: C-INT-DAT-05

## Description
An attacker inserts malicious data into the client's stream, intended to be stored or processed.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | The attacker injects illegitimate shards into the client's write/read stream. | Content-hash recompute on receipt and AES-256-GCM AEAD rejecting any shard not produced by client-side encryption. |
| Exploitation for Client Execution | T1203 | The injected malicious data aims to be processed by the client to trigger unintended behaviour. | Treating shards as opaque, hash-addressed ciphertext, verified before any decryption, with no interpretation by the nodes. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Content-hash recompute on receipt | T1565.002 | D3-FH | SI-7 |
| Client-side AES-256-GCM encryption | T1565.002 | D3-MENCR | SC-28 |
| "Dumb/untrusted" node + re-verification on the User side | T1203 | — | SA-8 |
| CTID controls (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| CTID controls (neo4j) | T1203 | — | AC-4, AC-6, CA-7, CM-8, SC-2, SC-3, SC-7, SC-18, SC-29, SC-30, SC-39, SC-44, SI-2, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.002 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1203 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
