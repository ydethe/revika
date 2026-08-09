# C-INT-MET-01 — Falsification

- **Target**: Clients
- **Category**: Integrity › Metadata
- **Identifier**: C-INT-MET-01

## Description
The metadata of a client manifest (structure, keys, pointers) is falsified to deceive reconstruction or access.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | The structure, keys or pointers of the manifest are modified to divert reconstruction or access. | Ed25519-signed manifest with content-hash shard pointers, any falsification invalidating the signature or the hash verification. |
| Masquerading | T1036 | A falsified manifest passes itself off as a legitimate manifest to deceive the client. | Read capability (manifest location + ML-KEM-768 wrapped key) bound to the recipient's pubkey, preventing acceptance of a non-authenticated manifest. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned Ed25519-signed manifest | T1565.001 | D3-MAN | SI-7 |
| Content-hash addressing | T1565.001 | D3-FH | SI-7 |
| ML-KEM-768 wrapping (cap wrapping) | T1036 | D3-MENCR | SC-12 |
| CTID controls (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
