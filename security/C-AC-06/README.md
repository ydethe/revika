# C-AC-06 — Sharing of rights

- **Target**: Clients
- **Category**: Access control
- **Identifier**: C-AC-06

## Description
A client redistributes the access rights conferred on it to unauthorized third parties.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | The client passes the authentication material/capability it holds to a third party. | Sharing strictly by ML-KEM-768 encapsulation to the recipient's pubkey (never a plaintext copy) and revocable TTL capabilities. |
| Trusted Relationship | T1199 | The client abuses the trust granted to it to propagate access out of scope. | Signed, chained append-only audit log tracing shares, with revocation and rotation of the capabilities concerned. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ML-KEM-768 encapsulation (cap wrapping) | T1550 | D3-MENCR | SC-12 |
| Short-TTL capabilities + revocation | T1550 | — | AC-3 |
| Chained append-only logs + signed seq | T1199 | — | AU-9 |
| CTID controls (neo4j) | T1550 | — | AC-2, AC-5, AC-6, CM-5, CM-6, IA-2 |
| CTID controls (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| D3FEND techniques (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
